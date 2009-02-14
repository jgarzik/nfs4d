
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

#define _GNU_SOURCE
#include "nfs4d-config.h"
#include <sys/stat.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <syslog.h>
#include <glib.h>
#include "server.h"

enum {
	FSDB_PGSZ_INODES		= 1024,	/* inodes db4 page size */
	FSDB_PGSZ_USERGROUP		= 1024,	/* user/group db4 page size */
	FSDB_PGSZ_UG_IDX		= 1024,	/* u/g idx db4 page size */
	FSDB_PGSZ_DIRENT		= 1024,	/* dir entry db4 page size */
};

static void db4syslog(const DB_ENV *dbenv, const char *errpfx, const char *msg)
{
	syslog(LOG_WARNING, "%s: %s", errpfx, msg);
}

static int dirent_cmp(DB *db, const DBT *dbt1, const DBT *dbt2)
{
	const struct fsdb_de_key *a = dbt1->data;
	const struct fsdb_de_key *b = dbt2->data;
	nfsino_t a_inum = GUINT64_FROM_LE(a->inum);
	nfsino_t b_inum = GUINT64_FROM_LE(b->inum);
	int a_len = dbt1->size - sizeof(*a);
	int b_len = dbt2->size - sizeof(*b);
	int rc;

	if (a_inum < b_inum)
		return -1;
	if (a_inum > b_inum)
		return 1;

	rc = memcmp(a->name, b->name, MIN(a_len, b_len));
	if (rc)
		return rc;
	
	return a_len - b_len;
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
		   unsigned int page_size, DBTYPE dbtype, unsigned int flags,
		   int (*bt_compare)(DB *db, const DBT *dbt1, const DBT *dbt2))
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

	if (bt_compare) {
		rc = db->set_bt_compare(db, dirent_cmp);
		if (rc) {
			db->err(db, rc, "db->set_bt_compare");
			rc = -EIO;
			goto err_out;
		}
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
		     DB_HASH, flags, NULL);
	if (rc)
		goto err_out;

	rc = open_db(dbenv, &fsdb->usergroup, "usergroup", FSDB_PGSZ_USERGROUP,
		     DB_HASH, flags, NULL);
	if (rc)
		goto err_out_inodes;

	rc = open_db(dbenv, &fsdb->ug_idx, "ug_idx",
		     FSDB_PGSZ_UG_IDX, DB_HASH, flags | DB_DUP, NULL);
	if (rc)
		goto err_out_ug;

	/* associate this secondary index with 'usergroup' primary db */
	rc = fsdb->usergroup->associate(fsdb->usergroup, NULL,
			fsdb->ug_idx, usergroup_idx_key, DB_CREATE);
	if (rc) {
		dbenv->err(dbenv, rc, "usergroup->associate");
		goto err_out_ug;
	}

	rc = open_db(dbenv, &fsdb->dirent, "dirent", FSDB_PGSZ_DIRENT,
		     DB_BTREE, flags, dirent_cmp);
	if (rc)
		goto err_out_ug_idx;

	return 0;

err_out_ug_idx:
	fsdb->ug_idx->close(fsdb->ug_idx, 0);
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
	fsdb->dirent->close(fsdb->dirent, 0);
	fsdb->ug_idx->close(fsdb->ug_idx, 0);
	fsdb->usergroup->close(fsdb->usergroup, 0);
	fsdb->inodes->close(fsdb->inodes, 0);
	fsdb->env->close(fsdb->env, 0);

	fsdb->env = NULL;
	fsdb->inodes = NULL;
	fsdb->usergroup = NULL;
	fsdb->ug_idx = NULL;
	fsdb->dirent = NULL;
}

int fsdb_dirent_get(struct fsdb *fsdb, DB_TXN *txn, nfsino_t inum,
		    const struct nfs_buf *str, int flags, nfsino_t *inum_out)
{
	DB *dirent = fsdb->dirent;
	DBT pkey, pval;
	int rc;
	size_t alloc_len;
	struct fsdb_de_key *key;
	nfsino_t *v;

	memset(&pkey, 0, sizeof(pkey));
	memset(&pval, 0, sizeof(pval));

	alloc_len = sizeof(*key) + str->len;
	key = alloca(alloc_len);
	key->inum = GUINT64_TO_LE(inum);
	memcpy(key->name, str->val, str->len);

	pkey.data = key;
	pkey.size = alloc_len;

	rc = dirent->get(dirent, txn, &pkey, &pval, flags);
	if (rc) {
		 if (rc != DB_NOTFOUND)
		 	dirent->err(dirent, rc, "dirent->get");
		 return rc;
	}

	v = pval.data;
	if (inum_out)
		*inum_out = GUINT64_FROM_LE(*v);

	return 0;
}

int fsdb_dirent_put(struct fsdb *fsdb, DB_TXN *txn, nfsino_t dir_inum,
		    const struct nfs_buf *str, int flags, nfsino_t de_inum)
{
	DB *dirent = fsdb->dirent;
	DBT pkey, pval;
	int rc;
	size_t alloc_len;
	struct fsdb_de_key *key;
	nfsino_t de_inum_le = GUINT64_TO_LE(de_inum);

	memset(&pkey, 0, sizeof(pkey));
	memset(&pval, 0, sizeof(pval));

	alloc_len = sizeof(*key) + str->len;
	key = alloca(alloc_len);
	key->inum = GUINT64_TO_LE(dir_inum);
	memcpy(key->name, str->val, str->len);

	pkey.data = key;
	pkey.size = alloc_len;

	pval.data = &de_inum_le;
	pval.size = sizeof(de_inum_le);

	rc = dirent->put(dirent, txn, &pkey, &pval, flags);
	if (rc) {
	 	dirent->err(dirent, rc, "dirent->put");
		return rc;
	}

	return 0;
}

int fsdb_dirent_del(struct fsdb *fsdb, DB_TXN *txn, nfsino_t dir_inum,
		    const struct nfs_buf *str, int flags)
{
	DB *dirent = fsdb->dirent;
	DBT pkey;
	int rc;
	size_t alloc_len;
	struct fsdb_de_key *key;

	memset(&pkey, 0, sizeof(pkey));

	alloc_len = sizeof(*key) + str->len;
	key = alloca(alloc_len);
	key->inum = GUINT64_TO_LE(dir_inum);
	memcpy(key->name, str->val, str->len);

	pkey.data = key;
	pkey.size = alloc_len;

	rc = dirent->del(dirent, txn, &pkey, flags);
	if (rc) {
 		dirent->err(dirent, rc, "dirent->del");
		return rc;
	}

	return 0;
}

int fsdb_inode_del(struct fsdb *fsdb, DB_TXN *txn, nfsino_t inum, int flags)
{
	DB *inodes = fsdb->inodes;
	DBT pkey;
	int rc;
	nfsino_t inum_le = GUINT64_TO_LE(inum);

	memset(&pkey, 0, sizeof(pkey));

	pkey.data = &inum_le;
	pkey.size = sizeof(inum_le);

	rc = inodes->del(inodes, txn, &pkey, flags);
	if (rc) {
 		inodes->err(inodes, rc, "inodes->del");
		return rc;
	}

	return 0;
}

int fsdb_inode_get(struct fsdb *fsdb, DB_TXN *txn, nfsino_t inum, int flags,
			struct fsdb_inode **dbino_out)
{
	DB *inodes = fsdb->inodes;
	DBT pkey, pval;
	int rc;
	nfsino_t inum_le = GUINT64_TO_LE(inum);

	memset(&pkey, 0, sizeof(pkey));
	memset(&pval, 0, sizeof(pval));

	pkey.data = &inum_le;
	pkey.size = sizeof(inum_le);

	rc = inodes->get(inodes, txn, &pkey, &pval, flags);
	if (rc) {
		 if (rc != DB_NOTFOUND)
		 	inodes->err(inodes, rc, "inodes->get");
		 return rc;
	}

	*dbino_out = pval.data;

	return 0;
}

int fsdb_inode_put(struct fsdb *fsdb, DB_TXN *txn,
		   struct fsdb_inode *ino, size_t ino_size, int flags)
{
	DB *inodes = fsdb->inodes;
	DBT pkey, pval;
	int rc;
	nfsino_t inum_le = GUINT64_TO_LE(ino->inum);

	memset(&pkey, 0, sizeof(pkey));
	memset(&pval, 0, sizeof(pval));

	pkey.data = &inum_le;
	pkey.size = sizeof(inum_le);

	pval.data = ino;
	pval.size = ino_size;

	rc = inodes->put(inodes, txn, &pkey, &pval, flags);
	if (rc) {
	 	inodes->err(inodes, rc, "inodes->put");
		return rc;
	}

	return 0;
}

int fsdb_inode_copyenc(struct fsdb_inode **dbino_o, size_t *dbino_len,
		       const struct nfs_inode *ino)
{
	size_t alloc_len = sizeof(struct fsdb_inode);
	struct fsdb_inode *dbino;
	void *p;
	uint16_t user_len = 0, group_len = 0, type_len = 0, link_len = 0;

	if (ino->user)
		user_len = strlen(ino->user);
	if (ino->group)
		group_len = strlen(ino->group);
	if (ino->mimetype)
		type_len = strlen(ino->mimetype);
	if (ino->linktext)
		link_len = strlen(ino->linktext);

	alloc_len += user_len + group_len + type_len + link_len;

	dbino = calloc(1, alloc_len);
	if (!dbino) {
		*dbino_o = NULL;
		return -ENOMEM;
	}

	dbino->inum = GUINT64_TO_LE(ino->inum);
	dbino->parent = GUINT64_TO_LE(ino->parent);
	dbino->version = GUINT64_TO_LE(ino->version);
	dbino->size = GUINT64_TO_LE(ino->size);
	dbino->ctime = GUINT64_TO_LE(ino->ctime);
	dbino->atime = GUINT64_TO_LE(ino->atime);
	dbino->mtime = GUINT64_TO_LE(ino->mtime);
	dbino->ftype = GUINT32_TO_LE(ino->type);
	dbino->mode = GUINT32_TO_LE(ino->mode);
	dbino->n_link = GUINT32_TO_LE(ino->n_link);
	dbino->devdata[0] = GUINT32_TO_LE(ino->devdata[0]);
	dbino->devdata[1] = GUINT32_TO_LE(ino->devdata[1]);
	memcpy(dbino->dataname, ino->dataname, sizeof(dbino->dataname));
	memcpy(dbino->create_verf, ino->create_verf, sizeof(dbino->create_verf));
	dbino->user_len = GUINT16_TO_LE(user_len);
	dbino->group_len = GUINT16_TO_LE(group_len);
	dbino->type_len = GUINT16_TO_LE(type_len);
	dbino->link_len = GUINT16_TO_LE(link_len);

	p = dbino;
	p += sizeof(*dbino);

	if (user_len) {
		memcpy(p, ino->user, user_len);
		p += user_len;
	}
	if (group_len) {
		memcpy(p, ino->group, group_len);
		p += group_len;
	}
	if (type_len) {
		memcpy(p, ino->mimetype, type_len);
		p += type_len;
	}
	if (link_len) {
		memcpy(p, ino->linktext, link_len);
		p += link_len;
	}

	*dbino_o = dbino;
	*dbino_len = alloc_len;
	return 0;
}

int fsdb_inode_putenc(struct fsdb *fsdb, DB_TXN *txn,
		      const struct nfs_inode *ino, int flags)
{
	size_t alloc_len;
	struct fsdb_inode *dbino = NULL;
	int rc;

	rc = fsdb_inode_copyenc(&dbino, &alloc_len, ino);
	if (rc)
		return rc;
	
	rc = fsdb_inode_put(fsdb, txn, dbino, alloc_len, flags);

	free(dbino);

	return rc;
}

static char *copy_binstr(const char *s_in, size_t s_len)
{
	char *s = malloc(s_len + 1);
	if (!s)
		return NULL;
	
	memcpy(s, s_in, s_len);
	s[s_len] = 0;

	return s;
}

int fsdb_inode_copydec(struct nfs_inode **ino_io, const struct fsdb_inode *dbino)
{
	struct nfs_inode *ino = *ino_io;
	const void *p;
	uint16_t tmp;

	if (!ino) {
		ino = calloc(1, sizeof(struct nfs_inode));
		if (!ino)
			return -ENOMEM;
	}

	ino->inum = GUINT64_FROM_LE(dbino->inum);
	ino->parent = GUINT64_FROM_LE(dbino->parent);
	ino->type = GUINT32_FROM_LE(dbino->ftype);
	ino->version = GUINT64_FROM_LE(dbino->version);

	/* note we use sizeof(dbino->...) because its dataname is smaller */
	memcpy(ino->dataname, dbino->dataname, sizeof(dbino->dataname));
	ino->dataname[sizeof(ino->dataname) - 1] = 0;

	memcpy(ino->create_verf, dbino->create_verf, sizeof(ino->create_verf));
	ino->size = GUINT64_FROM_LE(dbino->size);
	ino->ctime = GUINT64_FROM_LE(dbino->ctime);
	ino->atime = GUINT64_FROM_LE(dbino->atime);
	ino->mtime = GUINT64_FROM_LE(dbino->mtime);
	ino->mode = GUINT32_FROM_LE(dbino->mode);
	ino->n_link = GUINT32_FROM_LE(dbino->n_link);
	ino->devdata[0] = GUINT32_FROM_LE(dbino->devdata[0]);
	ino->devdata[1] = GUINT32_FROM_LE(dbino->devdata[1]);

	p = dbino;
	p += sizeof(*dbino);

	tmp = GUINT16_FROM_LE(dbino->user_len);
	if (tmp) {
		 ino->user = copy_binstr(p, tmp);
		 p += tmp;
	}

	tmp = GUINT16_FROM_LE(dbino->group_len);
	if (tmp) {
		 ino->group = copy_binstr(p, tmp);
		 p += tmp;
	}

	tmp = GUINT16_FROM_LE(dbino->type_len);
	if (tmp) {
		 ino->mimetype = copy_binstr(p, tmp);
		 p += tmp;
	}

	tmp = GUINT16_FROM_LE(dbino->link_len);
	if (tmp) {
		 ino->linktext = copy_binstr(p, tmp);
		 p += tmp;
	}

	*ino_io = ino;
	return 0;
}

int fsdb_inode_getdec(struct fsdb *fsdb, DB_TXN *txn, nfsino_t inum, int flags,
		      struct nfs_inode **ino_o)
{
	struct fsdb_inode *dbino = NULL;
	struct nfs_inode *ino = NULL;
	int rc;

	rc = fsdb_inode_get(fsdb, txn, inum, flags, &dbino);
	if (rc)
		return rc;

	rc = fsdb_inode_copydec(&ino, dbino);
	if (rc)
		return rc;
	
	*ino_o = ino;
	return 0;
}

