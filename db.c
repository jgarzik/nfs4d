
/*
 * Copyright 2008-2009 Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING.  If not, write to
 * the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#include "nfs4d-config.h"
#include <sys/stat.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <syslog.h>
#include <glib.h>
#include "fsdb.h"

enum {
	FSDB_PGSZ_INODES		= 1024,	/* inodes db4 page size */
	FSDB_PGSZ_USERGROUP		= 1024,	/* user/group db4 page size */
	FSDB_PGSZ_UG_IDX		= 1024,	/* u/g idx db4 page size */
};

static void db4syslog(const DB_ENV *dbenv, const char *errpfx, const char *msg)
{
	syslog(LOG_WARNING, "%s: %s", errpfx, msg);
}

static int usergroup_idx_key(DB *secondary, const DBT *pkey, const DBT *pdata,
			     DBT *key_out)
{
	const struct fsdb_ug_key *key = pkey->data;
	const uint32_t *val = pdata->data;
	struct fsdb_ugidx_key *ikey;

	ikey = malloc(sizeof(*ikey));
	if (!ikey)
		return ENOMEM;

	ikey->is_user = key->is_user;
	ikey->id = *val;

	memset(key_out, 0, sizeof(*key_out));

	key_out->flags = DB_DBT_APPMALLOC;
	key_out->data = ikey;
	key_out->size = sizeof(*ikey);

	return 0;
}

static int open_db(DB_ENV *env, DB **db_out, const char *name,
		   unsigned int page_size, DBTYPE dbtype, unsigned int flags)
{
	int rc;
	DB *db;

	rc = db_create(db_out, env, 0);
	if (rc) {
		env->err(env, rc, "db_create");
		return -EIO;
	}

	db = *db_out;

	rc = db->set_pagesize(db, page_size);
	if (rc) {
		db->err(db, rc, "db->set_pagesize");
		rc = -EIO;
		goto err_out;
	}

	/* fix everything as little endian */
	rc = db->set_lorder(db, 1234);
	if (rc) {
		db->err(db, rc, "db->set_lorder");
		rc = -EIO;
		goto err_out;
	}

	rc = db->open(db, NULL, name, NULL, dbtype,
		      DB_AUTO_COMMIT | flags, S_IRUSR | S_IWUSR);
	if (rc) {
		db->err(db, rc, "db->open");
		rc = -EIO;
		goto err_out;
	}

	return 0;

err_out:
	db->close(db, 0);
	return rc;
}

int fsdb_open(struct fsdb *fsdb, unsigned int env_flags, unsigned int flags,
	     const char *errpfx, bool do_syslog)
{
	const char *db_home, *db_password;
	int rc;
	DB_ENV *dbenv;

	/*
	 * open DB environment
	 */

	db_home = fsdb->home;
	g_assert(db_home != NULL);

	/* this isn't a very secure way to handle passwords */
	db_password = fsdb->key;

	rc = db_env_create(&fsdb->env, 0);
	if (rc) {
		fprintf(stderr, "fsdb->env_create failed: %d\n", rc);
		return rc;
	}

	dbenv = fsdb->env;

	dbenv->set_errpfx(dbenv, errpfx);

	if (do_syslog)
		dbenv->set_errcall(dbenv, db4syslog);
	else
		dbenv->set_errfile(dbenv, stderr);

	if (db_password) {
		flags |= DB_ENCRYPT;
		rc = dbenv->set_encrypt(dbenv, db_password, DB_ENCRYPT_AES);
		if (rc) {
			dbenv->err(dbenv, rc, "dbenv->set_encrypt");
			goto err_out;
		}

		memset(fsdb->key, 0, strlen(fsdb->key));
		free(fsdb->key);
		fsdb->key = NULL;
	}

	/* init DB transactional environment, stored in directory db_home */
	rc = dbenv->open(dbenv, db_home,
			 env_flags |
			 DB_INIT_LOG | DB_INIT_LOCK | DB_INIT_MPOOL |
			 DB_INIT_TXN, S_IRUSR | S_IWUSR);
	if (rc) {
		if (dbenv)
			dbenv->err(dbenv, rc, "dbenv->open");
		else
			fprintf(stderr, "dbenv->open failed: %d\n", rc);
		goto err_out;
	}

	/*
	 * Open databases
	 */

	rc = open_db(dbenv, &fsdb->inodes, "inodes", FSDB_PGSZ_INODES,
		     DB_HASH, flags);
	if (rc)
		goto err_out;

	rc = open_db(dbenv, &fsdb->usergroup, "usergroup", FSDB_PGSZ_USERGROUP,
		     DB_HASH, flags);
	if (rc)
		goto err_out_inodes;

	rc = open_db(dbenv, &fsdb->ug_idx, "ug_idx",
		     FSDB_PGSZ_UG_IDX, DB_HASH, flags | DB_DUP);
	if (rc)
		goto err_out_ug;

	/* associate this secondary index with 'usergroup' primary db */
	rc = fsdb->usergroup->associate(fsdb->usergroup, NULL,
			fsdb->ug_idx, usergroup_idx_key, DB_CREATE);
	if (rc) {
		dbenv->err(dbenv, rc, "usergroup->associate");
		goto err_out_ug;
	}

	return 0;

err_out_ug:
	fsdb->usergroup->close(fsdb->usergroup, 0);
err_out_inodes:
	fsdb->inodes->close(fsdb->inodes, 0);
err_out:
	dbenv->close(dbenv, 0);
	return rc;
}

void fsdb_close(struct fsdb *fsdb)
{
	fsdb->ug_idx->close(fsdb->ug_idx, 0);
	fsdb->usergroup->close(fsdb->usergroup, 0);
	fsdb->inodes->close(fsdb->inodes, 0);
	fsdb->env->close(fsdb->env, 0);

	fsdb->env = NULL;
	fsdb->inodes = NULL;
	fsdb->usergroup = NULL;
	fsdb->ug_idx = NULL;
}

