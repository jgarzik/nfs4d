
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
	FSDB_PGSZ_INODES		= 4096,	/* inodes db4 page size */
	FSDB_PGSZ_DIRENT		= 4096,	/* dir entry db4 page size */
	FSDB_PGSZ_CLIENTS		= 512,
	FSDB_PGSZ_CLIENT_OWNERS		= 512,
	FSDB_PGSZ_SESSIONS		= 512,

	FSDB_XDR_OUTBUF_SZ		= 4096,
};

static int fsdb_clients_getkey(DB *secondary,
			       const DBT *pkey, const DBT *pdata, DBT *skey);

static void db4syslog(const DB_ENV *dbenv, const char *errpfx, const char *msg)
{
	applog(LOG_WARNING, "%s: %s", errpfx, msg);
}

static int dirent_cmp(DB *db, const DBT *dbt1, const DBT *dbt2)
{
	const struct fsdb_de_key *a = dbt1->data;
	const struct fsdb_de_key *b = dbt2->data;
	nfsino_t a_inum = inum_decode(a->inum);
	nfsino_t b_inum = inum_decode(b->inum);
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
		rc = db->set_bt_compare(db, bt_compare);
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

	/* enable automatic deadlock detection */
	rc = dbenv->set_lk_detect(dbenv, DB_LOCK_DEFAULT);
	if (rc) {
		dbenv->err(dbenv, rc, "set_lk_detect");
		goto err_out;
	}

	/* enable automatic removal of unused logs.  should be re-examined
	 * once this project is more mature, as this makes catastrophic
	 * recovery more difficult.
	 */
	rc = dbenv->log_set_config(dbenv, DB_LOG_AUTO_REMOVE, 1);
	if (rc) {
		dbenv->err(dbenv, rc, "log_set_config");
		goto err_out;
	}

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

	if (fsdb->txn_nosync) {
		rc = dbenv->set_flags(dbenv, DB_TXN_NOSYNC, 1);
		if (rc) {
			dbenv->err(dbenv, rc, "dbenv->set_flags(TXN_NOSYNC)");
			goto err_out;
		}
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

	rc = open_db(dbenv, &fsdb->dirent, "dirent", FSDB_PGSZ_DIRENT,
		     DB_BTREE, flags, dirent_cmp);
	if (rc)
		goto err_out_inodes;

	rc = open_db(dbenv, &fsdb->clients, "clients", FSDB_PGSZ_CLIENTS,
		     DB_HASH, flags, NULL);
	if (rc)
		goto err_out_dirent;

	rc = open_db(dbenv, &fsdb->sessions, "sessions", FSDB_PGSZ_SESSIONS,
		     DB_HASH, flags, NULL);
	if (rc)
		goto err_out_clients;

	rc = open_db(dbenv, &fsdb->client_owners, "client_owners",
		     FSDB_PGSZ_CLIENT_OWNERS, DB_HASH, flags, NULL);
	if (rc)
		goto err_out_sessions;

	rc = fsdb->clients->associate(fsdb->clients, NULL,
				      fsdb->client_owners,
				      fsdb_clients_getkey, 0);
	if (rc)
		goto err_out_client_owners;

	return 0;

err_out_client_owners:
	fsdb->client_owners->close(fsdb->client_owners, 0);
err_out_sessions:
	fsdb->sessions->close(fsdb->sessions, 0);
err_out_clients:
	fsdb->clients->close(fsdb->clients, 0);
err_out_dirent:
	fsdb->dirent->close(fsdb->dirent, 0);
err_out_inodes:
	fsdb->inodes->close(fsdb->inodes, 0);
err_out:
	dbenv->close(dbenv, 0);
	return rc;
}

void fsdb_close(struct fsdb *fsdb)
{
	fsdb->client_owners->close(fsdb->client_owners, 0);
	fsdb->sessions->close(fsdb->sessions, 0);
	fsdb->clients->close(fsdb->clients, 0);
	fsdb->dirent->close(fsdb->dirent, 0);
	fsdb->inodes->close(fsdb->inodes, 0);
	fsdb->env->close(fsdb->env, 0);

	fsdb->env = NULL;
	fsdb->inodes = NULL;
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
	nfsino_t v;

	alloc_len = sizeof(*key) + str->len;
	key = alloca(alloc_len);
	key->inum = inum_encode(inum);
	memcpy(key->name, str->val, str->len);

	memset(&pkey, 0, sizeof(pkey));
	pkey.data = key;
	pkey.size = alloc_len;

	memset(&pval, 0, sizeof(pval));
	pval.data = &v;
	pval.ulen = sizeof(v);
	pval.flags = DB_DBT_USERMEM;

	rc = dirent->get(dirent, txn, &pkey, &pval, flags);
	if (rc) {
		 if (rc != DB_NOTFOUND)
		 	dirent->err(dirent, rc, "dirent->get");
		 return rc;
	}

	if (inum_out)
		*inum_out = inum_decode(v);

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
	nfsino_t de_inum_le = inum_encode(de_inum);

	memset(&pkey, 0, sizeof(pkey));
	memset(&pval, 0, sizeof(pval));

	alloc_len = sizeof(*key) + str->len;
	key = alloca(alloc_len);
	key->inum = inum_encode(dir_inum);
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
	key->inum = inum_encode(dir_inum);
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
	nfsino_t inum_le = inum_encode(inum);

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
	nfsino_t inum_le = inum_encode(inum);

	memset(&pkey, 0, sizeof(pkey));
	pkey.data = &inum_le;
	pkey.size = sizeof(inum_le);

	memset(&pval, 0, sizeof(pval));
	pval.flags = DB_DBT_MALLOC;

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
	nfsino_t inum_le = inum_encode(ino->inum);

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

	dbino->inum = inum_encode(ino->inum);
	dbino->parent = inum_encode(ino->parent);
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

	ino->inum = inum_decode(dbino->inum);
	ino->parent = inum_decode(dbino->parent);
	ino->type = GUINT32_FROM_LE(dbino->ftype);
	ino->version = GUINT64_FROM_LE(dbino->version);

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

	free(dbino);

	if (rc)
		return rc;

	*ino_o = ino;
	return 0;
}

void fsdb_cli_free(fsdb_client *cli, bool free_struct)
{
	xdr_free((xdrproc_t) xdr_fsdb_client, (char *) cli);

	if (free_struct)
		free(cli);
}

bool fsdb_cli_decode(const void *data, size_t size, fsdb_client *cli_out)
{
	bool xdr_rc;
	XDR xdrs;

	memset(cli_out, 0, sizeof(*cli_out));

	xdrmem_create(&xdrs, (void *) data, size, XDR_DECODE);

	xdr_rc = xdr_fsdb_client(&xdrs, cli_out);

	if (!xdr_rc) {
		fsdb_cli_free(cli_out, false);
		memset(cli_out, 0, sizeof(*cli_out));
	}

	xdr_destroy(&xdrs);

	return xdr_rc;
}

static int fsdb_clients_getkey(DB *secondary,
			       const DBT *pkey, const DBT *pdata, DBT *skey)
{
	fsdb_client cli;
	int rc = 0;

	/* TODO: calc and return pointer directly into pdata->data, 
	 * rather than less efficient alloc+copy
	 */

	if (!fsdb_cli_decode(pdata->data, pdata->size, &cli))
		return EIO;

	memset(skey, 0, sizeof(DBT));
	skey->data = memdup(cli.owner.owner_val, cli.owner.owner_len);
	skey->size = cli.owner.owner_len;
	skey->flags = DB_DBT_APPMALLOC;
	if (!skey->data)
		rc = ENOMEM;

	fsdb_cli_free(&cli, false);

	return rc;
}

int fsdb_cli_get(struct fsdb *fsdb, DB_TXN *txn, fsdb_client_id id,
		 int flags, fsdb_client *cli_out)
{
	DB *clients = fsdb->clients;
	DBT pkey, pval;
	int rc;
	bool xdr_rc;
	uint64_t id_be = GUINT64_TO_BE(id);

	memset(&pkey, 0, sizeof(pkey));
	pkey.data = &id_be;
	pkey.size = sizeof(id_be);

	memset(&pval, 0, sizeof(pval));

	rc = clients->get(clients, txn, &pkey, &pval, flags);
	if (rc) {
		 if (rc != DB_NOTFOUND)
		 	clients->err(clients, rc, "clients->get");
		 return rc;
	}

	xdr_rc = fsdb_cli_decode(pval.data, pval.size, cli_out);

	return xdr_rc ? 0 : -1;
}

int fsdb_cli_get_byowner(struct fsdb *fsdb, DB_TXN *txn,
			 struct nfs_constbuf *owner,
			 int flags, fsdb_client *cli_out)
{
	DB *client_owners = fsdb->client_owners;
	DBT pkey, pval;
	int rc;
	bool xdr_rc;

	memset(&pkey, 0, sizeof(pkey));
	pkey.data = (char *) owner->val;
	pkey.size = owner->len;

	memset(&pval, 0, sizeof(pval));

	rc = client_owners->get(client_owners, txn, &pkey, &pval, flags);
	if (rc) {
		 if (rc != DB_NOTFOUND)
		 	client_owners->err(client_owners, rc,
					   "client_owners->get");
		 return rc;
	}

	xdr_rc = fsdb_cli_decode(pval.data, pval.size, cli_out);

	return xdr_rc ? 0 : -1;
}

int fsdb_cli_put(struct fsdb *fsdb, DB_TXN *txn, int flags,
		 const fsdb_client *cli)
{
	DB *clients = fsdb->clients;
	DBT pkey, pval;
	int rc = -1;
	uint64_t id_be = GUINT64_TO_BE(cli->id);
	XDR xdrs;
	void *outbuf;

	outbuf = malloc(FSDB_XDR_OUTBUF_SZ);
	if (!outbuf)
		return -ENOMEM;

	xdrmem_create(&xdrs, outbuf, FSDB_XDR_OUTBUF_SZ, XDR_ENCODE);

	if (!xdr_fsdb_client(&xdrs, (fsdb_client *) cli))
		goto out;

	memset(&pkey, 0, sizeof(pkey));
	pkey.data = &id_be;
	pkey.size = sizeof(id_be);

	memset(&pval, 0, sizeof(pval));
	pval.data = outbuf;
	pval.size = xdr_getpos(&xdrs);

	rc = clients->put(clients, txn, &pkey, &pval, flags);
	if (rc) {
		 if (rc != DB_NOTFOUND)
		 	clients->err(clients, rc, "clients->put");
		 goto out;
	}

	rc = 0;

out:
	xdr_destroy(&xdrs);
	free(outbuf);
	return rc;
}

int fsdb_cli_del(struct fsdb *fsdb, DB_TXN *txn, fsdb_client_id id,
		 int flags)
{
	DB *clients = fsdb->clients;
	DBT pkey, pval;
	int rc;
	uint64_t id_be = GUINT64_TO_BE(id);

	memset(&pkey, 0, sizeof(pkey));
	pkey.data = &id_be;
	pkey.size = sizeof(id_be);

	memset(&pval, 0, sizeof(pval));

	rc = clients->del(clients, txn, &pkey, flags);
	if (rc) {
		 if (rc != DB_NOTFOUND)
		 	clients->err(clients, rc, "clients->del");
		 return rc;
	}

	return 0;
}

void fsdb_sess_free(fsdb_session *sess, bool free_struct)
{
	xdr_free((xdrproc_t) xdr_fsdb_session, (char *) sess);

	if (free_struct)
		free(sess);
}

bool fsdb_sess_decode(const void *data, size_t size, fsdb_session *sess_out)
{
	bool xdr_rc;
	XDR xdrs;

	memset(sess_out, 0, sizeof(*sess_out));

	xdrmem_create(&xdrs, (void *) data, size, XDR_DECODE);

	xdr_rc = xdr_fsdb_session(&xdrs, sess_out);

	if (!xdr_rc) {
		fsdb_sess_free(sess_out, false);
		memset(sess_out, 0, sizeof(*sess_out));
	}

	xdr_destroy(&xdrs);

	return xdr_rc;
}

int fsdb_sess_get(struct fsdb *fsdb, DB_TXN *txn, const fsdb_session_id id,
		 int flags, fsdb_session *sess_out)
{
	DB *sessions = fsdb->sessions;
	DBT pkey, pval;
	int rc;
	bool xdr_rc;

	memset(&pkey, 0, sizeof(pkey));
	pkey.data = (char *) &id[0];
	pkey.size = sizeof(id);

	memset(&pval, 0, sizeof(pval));

	rc = sessions->get(sessions, txn, &pkey, &pval, flags);
	if (rc) {
		 if (rc != DB_NOTFOUND)
		 	sessions->err(sessions, rc, "sessions->get");
		 return rc;
	}

	xdr_rc = fsdb_sess_decode(pval.data, pval.size, sess_out);

	return xdr_rc ? 0 : -1;
}

int fsdb_sess_put(struct fsdb *fsdb, DB_TXN *txn, int flags,
		  const fsdb_session *sess)
{
	DB *sessions = fsdb->sessions;
	DBT pkey, pval;
	int rc = -1;
	XDR xdrs;
	void *outbuf;

	outbuf = malloc(FSDB_XDR_OUTBUF_SZ);
	if (!outbuf)
		return -ENOMEM;

	xdrmem_create(&xdrs, outbuf, FSDB_XDR_OUTBUF_SZ, XDR_ENCODE);

	if (!xdr_fsdb_session(&xdrs, (fsdb_session *) sess))
		goto out;

	memset(&pkey, 0, sizeof(pkey));
	pkey.data = (char *) &sess->id[0];
	pkey.size = sizeof(sess->id);

	memset(&pval, 0, sizeof(pval));
	pval.data = outbuf;
	pval.size = xdr_getpos(&xdrs);

	rc = sessions->put(sessions, txn, &pkey, &pval, flags);
	if (rc) {
		 if (rc != DB_NOTFOUND)
		 	sessions->err(sessions, rc, "sessions->put");
		 goto out;
	}

	rc = 0;

out:
	xdr_destroy(&xdrs);
	free(outbuf);
	return rc;
}

int fsdb_sess_del(struct fsdb *fsdb, DB_TXN *txn, const fsdb_session_id id,
		 int flags)
{
	DB *sessions = fsdb->sessions;
	DBT pkey, pval;
	int rc;

	memset(&pkey, 0, sizeof(pkey));
	pkey.data = (char *) &id[0];
	pkey.size = sizeof(id);

	memset(&pval, 0, sizeof(pval));

	rc = sessions->del(sessions, txn, &pkey, flags);
	if (rc) {
		 if (rc != DB_NOTFOUND)
		 	sessions->err(sessions, rc, "sessions->del");
		 return rc;
	}

	return 0;
}

