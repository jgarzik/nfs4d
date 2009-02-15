
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
#include <string.h>
#include <glib.h>
#include <syslog.h>
#include <string.h>
#include "server.h"
#include "nfs4_prot.h"

static bool has_slash(const struct nfs_buf *str)
{
	if (!str)
		return false;
	if (g_utf8_strchr(str->val, str->len, '/'))
		return true;
	return false;
}

static bool has_dots(const struct nfs_buf *str)
{
	if (!str)
		return false;
	if ((str->len == 1) &&
	    (!memcmp(str->val, ".", 1)))
		return true;
	if ((str->len == 2) &&
	    (!memcmp(str->val, "..", 2)))
		return true;
	return false;
}

nfsstat4 dir_curfh(DB_TXN *txn, const struct nfs_cxn *cxn,
		   struct nfs_inode **ino_out, int flags)
{
	nfsstat4 status;
	struct nfs_inode *ino;

	*ino_out = NULL;
	status = NFS4_OK;
	ino = inode_fhdec(txn, cxn->current_fh, flags);
	if (!ino) {
		status = NFS4ERR_NOFILEHANDLE;
		goto out;
	}

	*ino_out = ino;
	if (ino->type != NF4DIR) {
		/* NOTE: add NF4LNK tests at caller */
		status = NFS4ERR_NOTDIR;
	}

out:
	return status;
}

nfsstat4 dir_lookup(DB_TXN *txn, const struct nfs_inode *dir_ino,
		    const struct nfs_buf *str, int flags,
		    nfsino_t *inum_out)
{
	int rc;

	if (!dir_ino->mode)
		return NFS4ERR_ACCESS;
	if (dir_ino->type != NF4DIR) {
		if (dir_ino->type == NF4LNK)
			return NFS4ERR_SYMLINK;
		return NFS4ERR_NOTDIR;
	}
	if (!valid_utf8string(str))
		return NFS4ERR_INVAL;
	if (has_dots(str))
		return NFS4ERR_BADNAME;
	if (has_slash(str))
		return NFS4ERR_BADNAME;
	if (str->len > SRV_MAX_NAME)
		return NFS4ERR_NAMETOOLONG;

	rc = fsdb_dirent_get(&srv.fsdb, txn, dir_ino->inum, str,
			     flags, inum_out);

	if (rc == DB_NOTFOUND)
		return NFS4ERR_NOENT;
	if (rc)
		return NFS4ERR_IO;

	return NFS4_OK;
}

nfsstat4 nfs_op_lookup(struct nfs_cxn *cxn, struct curbuf *cur,
		       struct list_head *writes, struct rpc_write **wr)
{
	nfsstat4 status = NFS4_OK;
	struct nfs_inode *ino = NULL;
	bool printed = false;
	struct nfs_buf objname;
	nfsino_t inum;
	DB_TXN *txn = NULL;
	DB_ENV *dbenv = srv.fsdb.env;
	int rc;

	CURBUF(&objname);

	if (!objname.len) {
		status = NFS4ERR_INVAL;
		goto out;
	}
	if (!objname.val) {
		status = NFS4ERR_BADXDR;
		goto out;
	}

	if (objname.len > SRV_MAX_NAME) {
		status = NFS4ERR_NAMETOOLONG;
		goto out;
	}

	rc = dbenv->txn_begin(dbenv, NULL, &txn, 0);
	if (rc) {
		status = NFS4ERR_IO;
		dbenv->err(dbenv, rc, "DB_ENV->txn_begin");
		goto out;
	}

	status = dir_curfh(txn, cxn, &ino, 0);
	if (status != NFS4_OK) {
		if ((status == NFS4ERR_NOTDIR) &&
		    (ino->type == NF4LNK))
			status = NFS4ERR_SYMLINK;
		goto out_abort;
	}

	status = dir_lookup(txn, ino, &objname, 0, &inum);
	if (status != NFS4_OK)
		goto out_abort;

	rc = txn->commit(txn, 0);
	if (rc) {
		dbenv->err(dbenv, rc, "DB_ENV->txn_commit");
		status = NFS4ERR_IO;
		goto out;
	}

	fh_set(&cxn->current_fh, inum);

	if (debugging) {
		syslog(LOG_INFO, "op LOOKUP ('%.*s') -> %016llX",
		       objname.len,
		       objname.val,
		       (unsigned long long) cxn->current_fh.inum);
		printed = true;
	}

out:
	if (!printed) {
		if (debugging)
			syslog(LOG_INFO, "op LOOKUP ('%.*s')",
			       objname.len,
			       objname.val);
	}

	WR32(status);
	inode_free(ino);
	return status;

out_abort:
	if (txn->abort(txn))
		dbenv->err(dbenv, rc, "DB_ENV->txn_abort");
	goto out;
}

nfsstat4 nfs_op_lookupp(struct nfs_cxn *cxn, struct curbuf *cur,
		       struct list_head *writes, struct rpc_write **wr)
{
	nfsstat4 status = NFS4_OK;
	struct nfs_inode *ino = NULL;

	if (debugging)
		syslog(LOG_INFO, "op LOOKUPP");

	status = dir_curfh(NULL, cxn, &ino, 0);
	if (status != NFS4_OK)
		goto out;

	if (ino->inum == INO_ROOT) {	/* root inode, no parents */
		status = NFS4ERR_NOENT;
		goto out;
	}

	fh_set(&cxn->current_fh, ino->parent);

out:
	WR32(status);
	inode_free(ino);
	return status;
}

enum nfsstat4 dir_add(DB_TXN *txn, struct nfs_inode *dir_ino,
		      const struct nfs_buf *name_in,
		      struct nfs_inode *ent_ino)
{
	enum nfsstat4 status = NFS4_OK, lu_stat;
	int rc;

	lu_stat = dir_lookup(txn, dir_ino, name_in, 0, NULL);
	if (lu_stat != NFS4ERR_NOENT) {
		if (lu_stat == NFS4_OK)
			status = NFS4ERR_EXIST;
		else
			status = lu_stat;
		return status;
	}

	rc = fsdb_dirent_put(&srv.fsdb, txn, dir_ino->inum, name_in,
			     DB_NOOVERWRITE, ent_ino->inum);
	if (rc) {
		if (rc == DB_KEYEXIST)
			status = NFS4ERR_EXIST;
		else
			status = NFS4ERR_IO;
		goto out;
	}

	rc = inode_touch(txn, dir_ino);
	if (rc) {
		status = NFS4ERR_IO;
		goto out;
	}

out:
	return status;
}

nfsstat4 nfs_op_link(struct nfs_cxn *cxn, struct curbuf *cur,
		     struct list_head *writes, struct rpc_write **wr)
{
	nfsstat4 status;
	struct nfs_inode *dir_ino = NULL, *src_ino = NULL;
	struct nfs_buf newname;
	uint64_t before = 0, after = 0;
	DB_TXN *txn;
	DB_ENV *dbenv = srv.fsdb.env;
	int rc;

	CURBUF(&newname);

	if (debugging)
		syslog(LOG_INFO, "op LINK (%.*s)",
		       newname.len,
		       newname.val);

	/* verify input parameters */
	if (!valid_fh(cxn->current_fh) || !valid_fh(cxn->save_fh)) {
		status = NFS4ERR_NOFILEHANDLE;
		goto out;
	}
	if (newname.len > SRV_MAX_NAME) {
		status = NFS4ERR_NAMETOOLONG;
		goto out;
	}

	/* open transaction */
	rc = dbenv->txn_begin(dbenv, NULL, &txn, 0);
	if (rc) {
		status = NFS4ERR_IO;
		dbenv->err(dbenv, rc, "DB_ENV->txn_begin");
		goto out;
	}

	/* read source inode's directory inode */
	dir_ino = inode_fhdec(txn, cxn->current_fh, 0);
	if (!dir_ino) {
		status = NFS4ERR_NOFILEHANDLE;
		goto out_abort;
	}

	/* make sure target is a directory */
	if (dir_ino->type != NF4DIR) {
		status = NFS4ERR_NOTDIR;
		goto out_abort;
	}

	/* read source inode */
	src_ino = inode_fhdec(txn, cxn->save_fh, 0);
	if (!src_ino) {
		status = NFS4ERR_NOFILEHANDLE;
		goto out_abort;
	}

	/* make sure source is a regular file */
	if (src_ino->type == NF4REG) {
		if (src_ino->type == NF4DIR)
			status = NFS4ERR_ISDIR;
		else
			status = NFS4ERR_INVAL;
		goto out_abort;
	}

	before = dir_ino->version;

	/* add directory entry */
	status = dir_add(txn, dir_ino, &newname, src_ino);
	if (status != NFS4_OK)
		goto out_abort;

	after = dir_ino->version;

	/* update source inode */
	src_ino->n_link++;
	if (inode_touch(txn, src_ino)) {
		status = NFS4ERR_IO;
		goto out_abort;
	}

	/* close transaction */
	rc = txn->commit(txn, 0);
	if (rc) {
		dbenv->err(dbenv, rc, "DB_ENV->txn_commit");
		status = NFS4ERR_IO;
		goto out;
	}

out:
	WR32(status);
	if (status == NFS4_OK) {
		WR32(1);		/* cinfo.atomic */
		WR64(before);		/* cinfo.before */
		WR64(after);		/* cinfo.after */
	}
	inode_free(src_ino);
	inode_free(dir_ino);
	return status;

out_abort:
	if (txn->abort(txn))
		dbenv->err(dbenv, rc, "DB_ENV->txn_abort");
	goto out;
}

static bool dir_is_empty(DB_TXN *txn, struct nfs_inode *ino)
{
	int rc;
	DBC *cur = NULL;
	DB *dirent = srv.fsdb.dirent;
	DBT pkey, pval;
	struct fsdb_de_key key;
	nfsino_t rnum = 0;
	bool have_rnum = false;

	rc = dirent->cursor(dirent, txn, &cur, 0);
	if (rc) {
		dirent->err(dirent, rc, "dirent->cursor");
		return false;
	}

	memset(&pkey, 0, sizeof(pkey));
	memset(&pval, 0, sizeof(pval));

	key.inum = GUINT64_TO_LE(ino->inum);

	pkey.data = &key;
	pkey.size = sizeof(key);

	rc = cur->get(cur, &pkey, &pval, DB_SET_RANGE);
	if (rc == 0) {
		struct fsdb_de_key *rkey = pkey.data;

		rnum = GUINT64_FROM_LE(rkey->inum);
		have_rnum = true;
	} else if (rc != DB_NOTFOUND)
		dirent->err(dirent, rc, "dir_is_empty cur->get");

	rc = cur->close(cur);
	if (rc) {
		dirent->err(dirent, rc, "dirent->cursor close");
		return false;
	}

	if (have_rnum && (rnum != ino->inum))
		return true;

	return false;
}

nfsstat4 nfs_op_remove(struct nfs_cxn *cxn, struct curbuf *cur,
		       struct list_head *writes, struct rpc_write **wr)
{
	nfsstat4 status = NFS4_OK;
	struct nfs_inode *dir_ino = NULL, *target_ino = NULL;
	struct nfs_buf target;
	change_info4 cinfo = { true, 0, 0 };
	DB_TXN *txn = NULL;
	DB_ENV *dbenv = srv.fsdb.env;
	int rc;
	nfsino_t de_inum;

	CURBUF(&target);

	if (debugging)
		syslog(LOG_INFO, "op REMOVE ('%.*s')",
		       target.len,
		       target.val);

	if (target.len > SRV_MAX_NAME) {
		status = NFS4ERR_NAMETOOLONG;
		goto out;
	}

	if (!valid_utf8string(&target)) {
		status = NFS4ERR_INVAL;
		goto out;
	}
	if (has_dots(&target)) {
		status = NFS4ERR_BADNAME;
		goto out;
	}

	rc = dbenv->txn_begin(dbenv, NULL, &txn, 0);
	if (rc) {
		status = NFS4ERR_IO;
		dbenv->err(dbenv, rc, "DB_ENV->txn_begin");
		goto out;
	}

	/* reference container directory */
	status = dir_curfh(txn, cxn, &dir_ino, DB_RMW);
	if (status != NFS4_OK)
		goto out_abort;

	/* lookup target name in directory */
	status = dir_lookup(txn, dir_ino, &target, 0, &de_inum);
	if (status != NFS4_OK)
		goto out_abort;

	/* reference target inode */
	target_ino = inode_getdec(txn, de_inum, DB_RMW);
	if (!target_ino) {
		status = NFS4ERR_NOENT;
		goto out_abort;
	}

	/* prevent root dir deletion */
	if (target_ino->inum == INO_ROOT) {
		status = NFS4ERR_INVAL;
		goto out_abort;
	}

	/* prevent removal of non-empty dirs */
	if ((target_ino->type == NF4DIR) && !dir_is_empty(txn, target_ino)) {
		status = NFS4ERR_NOTEMPTY;
		goto out_abort;
	}

	/* remove target inode from directory */
	rc = fsdb_dirent_del(&srv.fsdb, txn, dir_ino->inum, &target, 0);
	if (rc) {
		status = NFS4ERR_IO;
		goto out_abort;
	}

	/* record directory change info */
	cinfo.before = dir_ino->version;

	rc = inode_touch(txn, dir_ino);
	if (rc) {
		status = NFS4ERR_IO;
		goto out_abort;
	}

	cinfo.after = dir_ino->version;

	/* remove link, possibly deleting inode */
	rc = inode_unlink(txn, target_ino);
	if (rc) {
		status = NFS4ERR_IO;
		goto out_abort;
	}

	rc = txn->commit(txn, 0);
	if (rc) {
		dbenv->err(dbenv, rc, "DB_ENV->txn_commit");
		status = NFS4ERR_IO;
		goto out;
	}

out:
	WR32(status);
	if (status == NFS4_OK) {
		WR32(cinfo.atomic ? 1 : 0);	/* cinfo.atomic */
		WR64(cinfo.before);		/* cinfo.before */
		WR64(cinfo.after);		/* cinfo.after */
	}
	inode_free(dir_ino);
	inode_free(target_ino);
	return status;

out_abort:
	if (txn->abort(txn))
		dbenv->err(dbenv, rc, "DB_ENV->txn_abort");
	goto out;
}

nfsstat4 nfs_op_rename(struct nfs_cxn *cxn, struct curbuf *cur,
		       struct list_head *writes, struct rpc_write **wr)
{
	nfsstat4 status = NFS4_OK;
	struct nfs_inode *src_dir = NULL, *target_dir = NULL;
	struct nfs_inode *old_file = NULL, *new_file = NULL;
	struct nfs_buf oldname, newname;
	change_info4 src = { true, 0, 0 };
	change_info4 target = { true, 0, 0 };
	DB_TXN *txn = NULL;
	DB_ENV *dbenv = srv.fsdb.env;
	int rc;
	nfsino_t old_dirent, new_dirent;

	CURBUF(&oldname);
	CURBUF(&newname);

	if (debugging)
		syslog(LOG_INFO, "op RENAME (OLD:%.*s, NEW:%.*s)",
		       oldname.len,
		       oldname.val,
		       newname.len,
		       newname.val);

	/* validate text input */
	if ((!valid_utf8string(&oldname)) ||
	    (!valid_utf8string(&newname))) {
		status = NFS4ERR_INVAL;
		goto out;
	}
	if (has_dots(&oldname) || has_dots(&newname)) {
		status = NFS4ERR_BADNAME;
		goto out;
	}

	rc = dbenv->txn_begin(dbenv, NULL, &txn, 0);
	if (rc) {
		status = NFS4ERR_IO;
		dbenv->err(dbenv, rc, "DB_ENV->txn_begin");
		goto out;
	}

	/* reference source, target directories.
	 * NOTE: src_dir and target_dir may point to the same object
	 */
	src_dir = inode_fhdec(txn, cxn->save_fh, DB_RMW);
	if (fh_equal(cxn->save_fh, cxn->current_fh))
		target_dir = src_dir;
	else
		target_dir = inode_fhdec(txn, cxn->current_fh, DB_RMW);
	if (!src_dir || !target_dir) {
		status = NFS4ERR_NOFILEHANDLE;
		goto out_abort;
	}
	if ((src_dir->type != NF4DIR) || (target_dir->type != NF4DIR)) {
		status = NFS4ERR_NOTDIR;
		goto out_abort;
	}

	/* lookup source, target names */
	status = dir_lookup(txn, src_dir, &oldname, 0, &old_dirent);
	if (status != NFS4_OK)
		goto out_abort;

	old_file = inode_getdec(txn, old_dirent, 0);
	if (!old_file) {
		status = NFS4ERR_NOENT;
		goto out_abort;
	}

	status = dir_lookup(txn, target_dir, &newname, 0, &new_dirent);
	if (status != NFS4_OK && status != NFS4ERR_NOENT)
		goto out_abort;

	/* if target (newname) is present, attempt to remove */
	if (status == NFS4_OK) {
		bool ok_to_remove = false;

		/* read to-be-deleted inode */
		new_file = inode_getdec(txn, new_dirent, DB_RMW);
		if (!new_file) {
			status = NFS4ERR_NOENT;
			goto out_abort;
		}

		/* do oldname and newname refer to same file? */
		if (old_file->inum == new_file->inum) {
			src.after =
			src.before = src_dir->version;
			target.after =
			target.before = target_dir->version;
			goto out_abort;
		}

		if (old_file->type != NF4DIR && new_file->type != NF4DIR)
			ok_to_remove = true;

		if (!ok_to_remove) {
			status = NFS4ERR_EXIST;
			goto out_abort;
		}

		/* remove target inode from directory */
		rc = fsdb_dirent_del(&srv.fsdb, txn, target_dir->inum,
				     &newname, 0);
		if (rc == 0)
			rc = inode_unlink(txn, new_file);

		if (rc) {
			status = NFS4ERR_IO;
			goto out_abort;
		}
	}

	new_dirent = old_dirent;

	/* delete entry from source directory; add to target directory */
	rc = fsdb_dirent_del(&srv.fsdb, txn, src_dir->inum, &oldname, 0);
	if (rc == 0)
		rc = fsdb_dirent_put(&srv.fsdb, txn, target_dir->inum,
				     &newname, 0, new_dirent);
	if (rc) {
		status = NFS4ERR_IO;
		goto out_abort;
	}

	/* record directory change info */
	src.before = src_dir->version;
	target.before = target_dir->version;

	/* update last-modified stamps of directory inodes */
	rc = inode_touch(txn, src_dir);
	if (rc == 0 && src_dir != target_dir)
		rc = inode_touch(txn, target_dir);
	if (rc) {
		status = NFS4ERR_IO;
		goto out_abort;
	}

	/* close the transaction */
	rc = txn->commit(txn, 0);
	if (rc) {
		dbenv->err(dbenv, rc, "DB_ENV->txn_commit");
		status = NFS4ERR_IO;
		goto out;
	}

	src.after = src_dir->version;
	target.after = target_dir->version;

out:
	WR32(status);
	if (status == NFS4_OK) {
		WR32(src.atomic ? 1 : 0); /* src cinfo.atomic */
		WR64(src.before);	/* src cinfo.before */
		WR64(src.after);	/* src cinfo.after */
		WR32(target.atomic ? 1 : 0); /* target cinfo.atomic */
		WR64(target.before);	/* target cinfo.before */
		WR64(target.after);	/* target cinfo.after */
	}
	inode_free(src_dir);
	if (src_dir != target_dir)
		inode_free(target_dir);
	inode_free(old_file);
	inode_free(new_file);
	return status;

out_abort:
	if (txn->abort(txn))
		dbenv->err(dbenv, rc, "DB_ENV->txn_abort");
	goto out;
}

struct readdir_info {
	uint64_t cookie;
	uint32_t dircount;
	uint32_t maxcount;
	uint64_t attr_request;

	uint32_t dir_pos;

	struct list_head *writes;
	struct rpc_write **wr;

	uint32_t *val_follows;

	nfsstat4 status;

	bool cookie_found;
	bool stop;
	bool hit_limit;
	bool first_time;

	unsigned int n_results;
};

static bool readdir_iter(DB_TXN *txn, const struct fsdb_de_key *key,
			 size_t key_len, nfsino_t dirent,
			 struct readdir_info *ri)
{
	uint64_t bitmap_out = 0;
	uint32_t dirlen, maxlen;
	struct nfs_fattr_set attr;
	struct nfs_inode *ino = NULL;
	struct list_head *writes = ri->writes;
	struct rpc_write **wr = ri->wr;
	size_t name_len;
	struct nfs_buf de_name;

	if (ri->stop)
		return true;

	if (!ri->cookie_found) {
		if (ri->cookie && (ri->dir_pos <= ri->cookie)) {
			ri->dir_pos++;
			return false;
		}
		ri->cookie_found = true;
	}

	ino = inode_getdec(txn, dirent, 0);
	if (!ino) {
		syslog(LOG_WARNING, "           WARNING: inode %016llX not found",
			(unsigned long long) dirent);
		/* FIXME: return via rdattr-error */
		ri->stop = true;
		ri->status = NFS4ERR_NOENT;
		return true;
	}

	memset(&attr, 0, sizeof(attr));

	fattr_fill(ino, &attr);

	name_len = key_len - sizeof(*key);

	dirlen = 8 + 4 + (XDR_QUADLEN(name_len) * 4);
	if (dirlen > ri->dircount) {
		ri->hit_limit = true;
		ri->stop = true;
		if (debugging > 1)
			syslog(LOG_DEBUG, "           iter: hit dir limit");
		goto out;
	}

	maxlen = 8 + 4 + (XDR_QUADLEN(name_len) * 4) +
		 16 + fattr_size(&attr) + 4;
	if (maxlen > ri->maxcount) {
		ri->hit_limit = true;
		ri->stop = true;
		if (debugging > 1)
			syslog(LOG_DEBUG, "           iter: hit max limit");
		goto out;
	}

	if (ri->first_time) {
		ri->first_time = false;

		/* FIXME: server verifier isn't the best for dir verf */
		WRMEM(&srv.instance_verf, sizeof(verifier4));	/* cookieverf */

		ri->val_follows = WRSKIP(4);
	}

	ri->dircount -= dirlen;
	ri->maxcount -= maxlen;

	/* write value to previous entry4.nextentry */
	*ri->val_follows = htonl(1);
	ri->val_follows = NULL;

	WR64(ri->dir_pos);		/* entry4.cookie */

	de_name.len = name_len;
	de_name.val = (void *) key->name; /* cast is ok: RO data is copied */
	WRBUF(&de_name);		/* entry4.name */

	/* entry4.attrs */
	attr.bitmap = ri->attr_request;
	ri->status = wr_fattr(&attr, &bitmap_out, writes, wr);
	if (ri->status != NFS4_OK)
		ri->stop = true;

	if (debugging)
		syslog(LOG_DEBUG, "   READDIR ent: '%.*s' (INO:%016llX MAP:%Lx WRLEN:%u)",
			(int) name_len, key->name,
			(unsigned long long) dirent,
			(unsigned long long) bitmap_out, (*wr)->len);

	ri->val_follows = WRSKIP(4);	/* entry4.nextentry */

	ri->n_results++;
	ri->dir_pos++;

out:
	inode_free(ino);
	fattr_free(&attr);
	if (ri->stop)
		return true;
	return false;
}

nfsstat4 nfs_op_readdir(struct nfs_cxn *cxn, struct curbuf *cur,
		        struct list_head *writes, struct rpc_write **wr)
{
	nfsstat4 status = NFS4_OK;
	struct nfs_inode *ino = NULL;
	uint32_t dircount, maxcount, *status_p;
	struct readdir_info ri;
	uint64_t cookie, attr_request;
	verifier4 *cookie_verf;
	DB_TXN *txn = NULL;
	DB *dirent = srv.fsdb.dirent;
	DB_ENV *dbenv = srv.fsdb.env;
	bool first_loop = true;
	DBT pkey, pval;
	struct fsdb_de_key key;
	int cget_flags;
	DBC *curs = NULL;
	int rc;

	cookie = CR64();
	cookie_verf = CURMEM(sizeof(verifier4));
	dircount = CR32();
	maxcount = CR32();
	attr_request = CURMAP();

	status_p = WRSKIP(4);

	if (debugging) {
		syslog(LOG_INFO, "op READDIR (COOKIE:%Lu DIR:%u MAX:%u MAP:%Lx)",
		       (unsigned long long) cookie,
		       dircount,
		       maxcount,
		       (unsigned long long) attr_request);

		print_fattr_bitmap("op READDIR", attr_request);
	}

	/* traditionally "." and "..", hardcoded */
	if (cookie == 1 || cookie == 2) {
		status = NFS4ERR_BAD_COOKIE;
		goto out;
	}
	/* don't permit request of write-only attrib */
	if (attr_request & fattr_write_only_mask) {
		status = NFS4ERR_INVAL;
		goto out;
	}

	/* FIXME: very, very, very poor verifier */
	if (cookie &&
	    memcmp(cookie_verf, &srv.instance_verf, sizeof(verifier4))) {
		status = NFS4ERR_NOT_SAME;
		goto out;
	}

	/* read inode of directory being read */
	status = dir_curfh(NULL, cxn, &ino, 0);
	if (status != NFS4_OK)
		goto out;
	if (ino->mode == 0) {
		status = NFS4ERR_ACCESS;
		goto out;
	}

	/* subtract READDIR4resok header and footer size */
	if (maxcount < 16) {
		status = NFS4ERR_TOOSMALL;
		goto out;
	}

	maxcount -= (8 + 4 + 4);

	/* verify within server limits */
	if (dircount > SRV_MAX_READ || maxcount > SRV_MAX_READ) {
		status = NFS4ERR_INVAL;
		goto out;
	}

	/* open transaction */
	rc = dbenv->txn_begin(dbenv, NULL, &txn, 0);
	if (rc) {
		status = NFS4ERR_IO;
		dbenv->err(dbenv, rc, "DB_ENV->txn_begin");
		goto out;
	}

	/* set up directory iteration */
	memset(&ri, 0, sizeof(ri));
	ri.cookie = cookie;
	ri.dircount = dircount;
	ri.maxcount = maxcount;
	ri.attr_request = attr_request;
	ri.status = NFS4_OK;
	ri.writes = writes;
	ri.wr = wr;
	ri.dir_pos = 3;
	ri.first_time = true;

	/* if dir is empty, skip directory interation loop completely */
	if (dir_is_empty(txn, ino)) {
		WRMEM(&srv.instance_verf, sizeof(verifier4));	/* cookieverf */

		ri.val_follows = WRSKIP(4);

		if (debugging)
			syslog(LOG_DEBUG, "   READDIR: empty directory");

		goto the_finale;
	}

	/* otherwise, loop through each dirent attached to ino->inum */
	rc = dirent->cursor(dirent, txn, &curs, 0);
	if (rc) {
		status = NFS4ERR_IO;
		dirent->err(dirent, rc, "dirent->cursor");
		goto out_abort;
	}

	memset(&pkey, 0, sizeof(pkey));
	memset(&pval, 0, sizeof(pval));

	key.inum = GUINT64_TO_LE(ino->inum);

	pkey.data = &key;
	pkey.size = sizeof(key);

	while (1) {
		struct fsdb_de_key *rkey;
		uint64_t dirent_inum, *dep;

		if (first_loop) {
			cget_flags = DB_SET_RANGE;
			first_loop = false;
		} else
			cget_flags = DB_NEXT;

		rc = curs->get(curs, &pkey, &pval, cget_flags);
		if (rc) {
			if (rc != DB_NOTFOUND)
				dirent->err(dirent, rc, "readdir curs->get");
			break;
		}

		rkey = pkey.data;
		if (GUINT64_FROM_LE(rkey->inum) != ino->inum)
			break;

		dep = pval.data;
		dirent_inum = GUINT64_FROM_LE(*dep);

		if (readdir_iter(txn, rkey, pkey.size, dirent_inum, &ri))
			break;
	}

	if (!ri.n_results) {
		if (debugging)
			syslog(LOG_INFO, "           zero results, status %s",
			       ri.status <= NFS4ERR_CB_PATH_DOWN ?
			       		name_nfs4status[ri.status] : "n/a");

		if (ri.status == NFS4_OK) {
			WRMEM(&srv.instance_verf, sizeof(verifier4));	/* cookieverf */

			ri.val_follows = WRSKIP(4);
		}
	}

	rc = curs->close(curs);
	if (rc) {
		status = NFS4ERR_IO;
		dirent->err(dirent, rc, "dirent->cursor close");
		goto out_abort;
	}

the_finale:

	/* terminate final entry4.nextentry and dirlist4.entries */
	if (ri.val_follows)
		*ri.val_follows = htonl(0);

	if (ri.cookie_found && !ri.n_results && ri.hit_limit) {
		status = NFS4ERR_TOOSMALL;
		goto out_abort;
	}

	/* close transaction */
	rc = txn->commit(txn, 0);
	if (rc) {
		dbenv->err(dbenv, rc, "DB_ENV->txn_commit");
		status = NFS4ERR_IO;
		goto out;
	}

	WR32(ri.hit_limit ? 0 : 1);		/* reply eof */

out:
	*status_p = htonl(status);
	inode_free(ino);
	return status;

out_abort:
	if (txn->abort(txn))
		dbenv->err(dbenv, rc, "DB_ENV->txn_abort");
	goto out;
}

