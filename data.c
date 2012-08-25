
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
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <syslog.h>
#include "server.h"

static const char *name_stable_how4[] = {
	[UNSTABLE4]		= "UNSTABLE4",
	[DATA_SYNC4]		= "DATA_SYNC4",
	[FILE_SYNC4]		= "FILE_SYNC4",
};

static const char *name_lock_type4[] = {
	[READ_LT]		= "READ_LT",
	[WRITE_LT]		= "WRITE_LT",
	[READW_LT]		= "READW_LT",
	[WRITEW_LT]		= "WRITEW_LT",
};

nfsstat4 nfs_op_commit(struct nfs_cxn *cxn, const COMMIT4args *args,
		       struct list_head *writes, struct rpc_write **wr)
{
	nfsstat4 status = NFS4_OK;
	struct nfs_inode *ino = NULL;
	uint64_t offset;
	uint32_t count;
	char *fdpath;
	int fd;
	char datapfx[4];

	/* read COMMIT args */
	offset = args->offset;
	count = args->count;

	if (debugging)
		applog(LOG_INFO, "op COMMIT (OFS:%Lu LEN:%x)",
		       (unsigned long long) offset, count);

	/* obtain and validate inode */
	ino = inode_fhdec(NULL, cxn->current_fh, 0);
	if (!ino) {
		status = NFS4ERR_NOFILEHANDLE;
		goto out;
	}

	/* we only support writing to regular files */
	if (ino->type != NF4REG) {
		if (ino->type == NF4DIR)
			status = NFS4ERR_ISDIR;
		else
			status = NFS4ERR_INVAL;
		goto out;
	}

	/* validate offset+count */
	if ((uint64_t) count > ~(uint64_t)offset) {
		status = NFS4ERR_INVAL;
		goto out;
	}

	mk_datapfx(datapfx, ino->inum);
	fdpath = alloca(strlen(srv.data_dir) + INO_FNAME_LEN + 1);
	sprintf(fdpath, INO_DATAFN_FMT, srv.data_dir, datapfx,
		(unsigned long long) ino->inum);

	fd = open(fdpath, O_WRONLY);
	if (fd < 0)
		goto err_io;

	if (fsync(fd) < 0)
		goto err_io_fd;

	if (close(fd) < 0)
		goto err_io;

out:
	WR32(status);
	if (status == NFS4_OK)
		WRMEM(&srv.instance_verf, sizeof(srv.instance_verf));
	inode_free(ino);
	return status;

err_io_fd:
	close(fd);
err_io:
	status = NFS4ERR_IO;
	goto out;
}

nfsstat4 nfs_op_write(struct nfs_cxn *cxn, const WRITE4args *args,
		      struct list_head *writes, struct rpc_write **wr)
{
	nfsstat4 status = NFS4_OK;
	struct nfs_stateid sid;
	struct nfs_inode *ino = NULL;
	uint64_t new_size, offset;
	stable_how4 stable;
	struct nfs_buf data;
	struct nfs_access ac = { NULL, };
	uint64_t old_size;
	int fd, frc;
	char *fdpath;
	size_t pending;
	void *p;
	DB_ENV *dbenv = srv.fsdb.env;
	DB_TXN *txn;
	int rc;
	char datapfx[4];

	copy_sid(&sid, &args->stateid);
	offset = args->offset;
	stable = args->stable;
	data.len = args->data.data_len;
	data.val = args->data.data_val;

	srv.stats.write_bytes += data.len;

	if (debugging)
		applog(LOG_INFO, "op WRITE (SID.SEQ:%u SID.ID:%x OFS:%Lu ST:%s LEN:%x)",
		       sid.seqid, sid.id,
		       (unsigned long long) offset,
		       name_stable_how4[stable],
		       data.len);

	if (data.len > SRV_MAX_WRITE)
		data.len = SRV_MAX_WRITE;

	/* open transaction */
	rc = dbenv->txn_begin(dbenv, NULL, &txn, 0);
	if (rc) {
		status = NFS4ERR_IO;
		dbenv->err(dbenv, rc, "DB_ENV->txn_begin");
		goto out;
	}

	/* read target inode */
	ino = inode_fhdec(txn, cxn->current_fh, DB_RMW);
	if (!ino) {
		status = NFS4ERR_NOFILEHANDLE;
		goto out_abort;
	}

	/* we only support writing to regular files */
	if (ino->type != NF4REG) {
		if (debugging)
			applog(LOG_INFO, "trying to write to file of type %s",
			       name_nfs_ftype4[ino->type]);
		if (ino->type == NF4DIR)
			status = NFS4ERR_ISDIR;
		else
			status = NFS4ERR_INVAL;
		goto out_abort;
	}

	old_size = ino->size;

	/* verify we have access to write */
	ac.sid = &sid;
	ac.ino = ino;
	ac.op = OP_WRITE;
	ac.ofs = offset;
	ac.len = data.len;
	status = access_ok(&ac);
	if (status != NFS4_OK)
		goto out_abort;

	/* if zero length, return success immediately */
	if (data.len == 0)
		goto out_commit;

	new_size = offset + data.len;
	if (new_size < old_size)
		new_size = old_size;

	/* build file path, open file */
	mk_datapfx(datapfx, ino->inum);
	fdpath = alloca(strlen(srv.data_dir) + INO_FNAME_LEN + 1);
	sprintf(fdpath, INO_DATAFN_FMT, srv.data_dir, datapfx,
		(unsigned long long) ino->inum);
	fd = open(fdpath, O_WRONLY);
	if (fd < 0) {
		syslogerr2("open", fdpath);
		goto err_io;
	}

	/* seek to desired write location */
	if (offset && lseek64(fd, offset, SEEK_SET) < 0) {
		syslogerr2("lseek64", fdpath);
		goto err_io_fd;
	}

	/* write data to file.  handle write(2) writing
	 * fewer less than requested bytes
	 */
	p = data.val;
	pending = data.len;
	while (pending > 0) {
		ssize_t wrc = write(fd, p, pending);
		if (wrc < 0) {
			syslogerr2("write", fdpath);
			goto err_io_fd;
		}

		pending -= wrc;
		p += wrc;
	}

	/* sync to storage, if requested */
	if (stable == FILE_SYNC4)
		frc = fsync(fd);
	else if (stable == DATA_SYNC4)
		frc = fdatasync(fd);
	else
		frc = 0;
	if (frc) {
		syslogerr2("f[data]sync", fdpath);
		goto err_io_fd;
	}

	/* close file */
	if (close(fd) < 0) {
		syslogerr2("close", fdpath);
		goto err_io;
	}

	/* reflect new file size in inode */
	ino->size = new_size;

	/* FIXME: ugh.  if inode_touch() or txn_commit() fail,
	 * we leave the just-written data in the data object.
	 */

	rc = inode_touch(txn, ino);
	if (rc) {
		status = NFS4ERR_IO;
		goto out_abort;
	}

out_commit:
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
		WR32(data.len);
		WR32(FILE_SYNC4);
		WRMEM(&srv.instance_verf, sizeof(verifier4));
	}
	inode_free(ino);
	return status;

err_io_fd:
	close(fd);
err_io:
	status = NFS4ERR_IO;

out_abort:
	if (txn->abort(txn))
		dbenv->err(dbenv, rc, "DB_ENV->txn_abort");
	goto out;
}

nfsstat4 nfs_op_read(struct nfs_cxn *cxn, const READ4args *args,
		     struct list_head *writes, struct rpc_write **wr)
{
	nfsstat4 status = NFS4_OK;
	struct nfs_stateid sid;
	struct nfs_inode *ino = NULL;
	uint64_t read_size = 0, offset, pad_size;
	uint32_t count;
	bool eof = false;
	struct nfs_access ac = { NULL, };
	struct rpc_write *data_wr = NULL, *pad_wr = NULL, *next_wr = NULL;
	int fd;
	char *fdpath;
	char datapfx[4];

	copy_sid(&sid, &args->stateid);
	offset = args->offset;
	count = args->count;

	srv.stats.read_bytes += count;

	if (debugging)
		applog(LOG_INFO, "op READ (IDSEQ:%u ID:%x OFS:%Lu LEN:%x)",
		       sid.seqid, sid.id,
		       (unsigned long long) offset, count);

	if (count > SRV_MAX_READ)
		count = SRV_MAX_READ;

	ino = inode_fhdec(NULL, cxn->current_fh, 0);
	if (!ino) {
		status = NFS4ERR_NOFILEHANDLE;
		goto out;
	}

	/* we only support reading from regular files */
	if (ino->type != NF4REG) {
		if (debugging)
			applog(LOG_INFO, "trying to read to file of type %s",
			       name_nfs_ftype4[ino->type]);
		if (ino->type == NF4DIR)
			status = NFS4ERR_ISDIR;
		else
			status = NFS4ERR_INVAL;
		goto out;
	}

	ac.sid = &sid;
	ac.ino = ino;
	ac.op = OP_READ;
	ac.ofs = offset;
	ac.len = count;
	status = access_ok(&ac);
	if (status != NFS4_OK)
		goto out;

	if (offset >= ino->size) {
		read_size = 0;
		eof = true;
		if (debugging > 1)
			applog(LOG_INFO, "        (read_size 0, EOF)");
		goto out;
	}
	if (count == 0) {
		if (debugging > 1)
			applog(LOG_INFO, "        (count 0, skip work)");
		goto out;
	}

	read_size = ino->size - offset;
	if (read_size > count)
		read_size = count;
	if (read_size > RPC_WRITE_BUFSZ)
		read_size = RPC_WRITE_BUFSZ;

	if (debugging > 1)
		applog(LOG_INFO, "        (read_size %llu)",
			(unsigned long long) read_size);

	next_wr = wr_alloc(0);
	data_wr = wr_alloc(read_size);
	if (!data_wr || !next_wr) {
		status = NFS4ERR_RESOURCE;
		goto err_out_data;
	}

	mk_datapfx(datapfx, ino->inum);
	fdpath = alloca(strlen(srv.data_dir) + INO_FNAME_LEN + 1);
	sprintf(fdpath, INO_DATAFN_FMT, srv.data_dir, datapfx,
		(unsigned long long) ino->inum);
	fd = open(fdpath, O_RDONLY);
	if (fd < 0) {
		syslogerr2("open", fdpath);
		goto err_io;
	}

	if (lseek64(fd, offset, SEEK_SET) < 0) {
		syslogerr2("lseek64", fdpath);
		goto err_io_fd;
	}

	if (read(fd, data_wr->rbuf->buf, read_size) != read_size) {
		syslogerr2("read", fdpath);
		goto err_io_fd;
	}

	if (close(fd) < 0) {
		syslogerr2("close", fdpath);
		goto err_io;
	}

	data_wr->len = read_size;

	pad_size = (XDR_QUADLEN(read_size) * 4) - read_size;
	if (pad_size) {
		pad_wr = wr_ref(&pad_rb, 0, pad_size);
		if (!pad_wr) {
			status = NFS4ERR_RESOURCE;
			goto err_out_data;
		}
	}

	if ((offset + read_size) >= ino->size)
		eof = true;

out:
	WR32(status);
	if (status == NFS4_OK) {
		WR32(eof);
		WR32(read_size);
		if (read_size) {
			list_add_tail(&data_wr->node, writes);
			if (pad_wr)
				list_add_tail(&pad_wr->node, writes);
			list_add_tail(&next_wr->node, writes);
			*wr = next_wr;
		}
	}
	inode_free(ino);
	return status;

err_io_fd:
	close(fd);
err_io:
	status = NFS4ERR_IO;
err_out_data:
	wr_free(data_wr);
	wr_free(next_wr);
	goto out;
}

nfsstat4 nfs_op_testlock(struct nfs_cxn *cxn, const LOCKT4args *args,
		         struct list_head *writes, struct rpc_write **wr)
{
	nfsstat4 status = NFS4_OK;
	struct nfs_inode *ino = NULL;
	nfs_lock_type4 locktype;
	uint64_t offset, length;
	clientid4 owner_id;
	struct nfs_buf owner;
	struct nfs_access ac = { NULL, };
	struct nfs_owner *o = NULL;

	/* read LOCKT args */
	locktype = args->locktype;
	offset = args->offset;
	length = args->length;
	owner_id = args->owner.clientid;
	owner.len = args->owner.owner.owner_len;
	owner.val = args->owner.owner.owner_val;

	if (debugging)
		applog(LOG_INFO, "op TESTLOCK (TYP:%s OFS:%Lu LEN:%Lx OCID:%Lx OWNER:%.*s)",
		       name_lock_type4[locktype],
		       (unsigned long long) offset,
		       (unsigned long long) length,
		       (unsigned long long) owner_id,
		       owner.len,
		       owner.val);

	/* validate length and offset+length */
	if (!length || ((length != ~0ULL) &&
		     ((uint64_t)length > ~(uint64_t)offset))) {
		status = NFS4ERR_INVAL;
		goto out;
	}

	/* grab and validate inode */
	ino = inode_fhdec(NULL, cxn->current_fh, 0);
	if (!ino) {
		status = NFS4ERR_NOFILEHANDLE;
		goto out;
	}

	/* we only support reading from regular files */
	if (ino->type != NF4REG) {
		if (debugging)
			applog(LOG_INFO, "trying to lock file of type %s",
			       name_nfs_ftype4[ino->type]);
		if (ino->type == NF4DIR)
			status = NFS4ERR_ISDIR;
		else
			status = NFS4ERR_INVAL;
		goto out;
	}

	/*
	 * find nfs_owner, given clientid and lock owner name
	 * 'o' may be NULL after this returns NFS4_OK.
	 */
	status = owner_lookup_name(owner_id, &owner, &o);
	if (status != NFS4_OK)
		goto out;

	ac.ino = ino;
	ac.op = OP_LOCKT;
	ac.locktype = locktype;
	ac.ofs = offset;
	ac.len = length;
	status = access_ok(&ac);

	/* if we found a matching lock, and it matches the
	 * owner given in the args, return success
	 */
	if (ac.match && (ac.match->owner == o)) {
		ac.match = NULL;
		status = NFS4_OK;
	}

out:
	if (ac.match) {
		WR32(NFS4ERR_DENIED);
		WR64(offset);			/* offset */
		WR64(length);			/* length */
		WR32(locktype);			/* lock type */
		WR64(ac.match->owner->cli);	/* owner id */
		WRSTR(ac.match->owner->owner);	/* owner name */
	} else
		WR32(status);
	inode_free(ino);
	return status;
}

static void print_lock_args(uint32_t prev_id_seq,
			    uint32_t prev_id, uint32_t locktype,
			    uint64_t offset, uint64_t length,
			    bool reclaim, bool new_lock,
			    uint32_t lseqid, uint32_t open_seqid,
			    uint64_t id_short, struct nfs_buf *owner)
{
	if (!debugging)
		return;

	applog(LOG_INFO, "op LOCK (NEW:%s LSEQ:%u TYP:%s REC:%s OFS:%Lu LEN:%Lx)",
	       new_lock ? "Y" : "N",
	       lseqid,
	       name_lock_type4[locktype],
	       reclaim ? "Y" : "N",
	       (unsigned long long) offset,
	       (unsigned long long) length);

	if (new_lock) {
		applog(LOG_INFO, "   LOCK (OSEQ:%u IDSEQ:%u ID:%x OCID:%Lx OWNER:%.*s)",
		       open_seqid,
		       prev_id_seq, prev_id,
		       (unsigned long long) id_short,
		       owner->len,
		       owner->val);
	} else {
		applog(LOG_INFO, "   LOCK (IDSEQ:%u ID:%x)",
		       prev_id_seq, prev_id);
	}
}

nfsstat4 nfs_op_lock(struct nfs_cxn *cxn, const LOCK4args *args,
		     struct list_head *writes, struct rpc_write **wr)
{
	nfsstat4 status = NFS4_OK;
	struct nfs_inode *ino = NULL;
	struct nfs_stateid *prev_sid;
	uint32_t prev_id;
	struct nfs_stateid *sid, lock_sid, open_sid, tmp_sid;
	bool reclaim, new_lock, new_lock_of = false;
	uint32_t lock_seqid, open_seqid = 0;
	nfs_lock_type4 locktype;
	uint64_t offset, length, id_short = 0;
	struct nfs_buf owner;
	struct nfs_lock *lock_ent;
	struct nfs_owner *open_owner = NULL, *conflict = NULL;
	struct nfs_owner *lock_owner = NULL;
	struct nfs_openfile *of = NULL, *lock_of = NULL;
	struct nfs_access ac = { NULL, };

	(void) new_lock_of;	/* silence set-but-not-used warning */

	cxn->drc_mask |= drc_lock;

	memset(&lock_sid, 0, sizeof(lock_sid));
	memset(&open_sid, 0, sizeof(open_sid));
	memset(&owner, 0, sizeof(owner));

	locktype = args->locktype;
	reclaim = args->reclaim;
	offset = args->offset;
	length = args->length;
	new_lock = args->locker.new_lock_owner;

	if (new_lock) {
		const open_to_lock_owner4 *o_owner =
			&args->locker.locker4_u.open_owner;

		open_seqid = o_owner->open_seqid;
		copy_sid(&open_sid, &o_owner->open_stateid);
		lock_seqid = o_owner->lock_seqid;
		id_short = o_owner->lock_owner.clientid;
		owner.len = o_owner->lock_owner.owner.owner_len;
		owner.val = o_owner->lock_owner.owner.owner_val;
	} else {
		copy_sid(&lock_sid,
			 &args->locker.locker4_u.lock_owner.lock_stateid);
		lock_seqid = args->locker.locker4_u.lock_owner.lock_seqid;
	}

	if (new_lock)
		prev_sid = &open_sid;
	else
		prev_sid = &lock_sid;

	prev_id = prev_sid->id;

	print_lock_args(prev_sid->seqid, prev_id, locktype, offset,
			length, reclaim, new_lock, lock_seqid,
			open_seqid, id_short, &owner);

	if (new_lock && (lock_seqid != 0)) {
		status = NFS4ERR_BAD_SEQID;
		goto out;
	}

	if (!length || ((length != ~0ULL) &&
		     ((uint64_t)length > ~(uint64_t)offset))) {
		status = NFS4ERR_INVAL;
		goto out;
	}

	if (reclaim) {
		status = NFS4ERR_NO_GRACE;
		goto out;
	}

	ino = inode_fhdec(NULL, cxn->current_fh, 0);
	if (!ino) {
		status = NFS4ERR_NOFILEHANDLE;
		goto out;
	}

	/* we only support reading from regular files */
	if (ino->type != NF4REG) {
		if (debugging)
			applog(LOG_INFO, "trying to lock file of type %s",
			       name_nfs_ftype4[ino->type]);
		if (ino->type == NF4DIR)
			status = NFS4ERR_ISDIR;
		else
			status = NFS4ERR_INVAL;
		goto out;
	}


	if (new_lock) {
		status = openfile_lookup(prev_sid, ino, nst_open, &of);
		if (status != NFS4_OK)
			goto out;

		if (open_seqid != of->owner->cli_next_seq) {
			status = NFS4ERR_BAD_SEQID;
			goto out;
		}

		of->owner->cli_next_seq++;

		if ((locktype == WRITE_LT || locktype == WRITEW_LT) &&
		    (of->share_access == OPEN4_SHARE_ACCESS_READ)) {
			status = NFS4ERR_OPENMODE;
			goto out;
		}
	} else {
		status = openfile_lookup(prev_sid, ino, nst_lock, &lock_of);
		if (status != NFS4_OK)
			goto out;
		lock_owner = lock_of->owner;

		if (lock_seqid != lock_of->owner->cli_next_seq) {
			status = NFS4ERR_BAD_SEQID;
			goto out;
		}

		of = lock_of->lock_open;
	}

	ac.sid = prev_sid;
	ac.ino = ino;
	ac.op = OP_LOCK;
	ac.locktype = locktype;
	ac.ofs = offset;
	ac.len = length;
	status = access_ok(&ac);
	if (ac.match)
		conflict = ac.match->owner;
	if (conflict || status != NFS4_OK)
		goto out;

	lock_ent = calloc(1, sizeof(struct nfs_lock));
	if (!lock_ent) {
		status = NFS4ERR_RESOURCE;
		goto out;
	}

	lock_ent->ofs = offset;
	lock_ent->len = length;
	INIT_LIST_HEAD(&lock_ent->node);
	lock_ent->type = locktype;

	/*
	 * otherwise, create new lock state
	 */
	if (new_lock) {

		/*
	 	* look up shorthand client id (clientid4) for new lock owner
	 	*/
		status = clientid_test(id_short);
		if (status != NFS4_OK)
			goto err_out;

		lock_owner = owner_new(nst_lock, &owner);
		if (!lock_owner) {
			status = NFS4ERR_RESOURCE;
			goto err_out;
		}

		lock_owner->cli = id_short;
		lock_owner->open_owner = open_owner;
		lock_owner->cli_next_seq = lock_seqid + 1;

		cli_owner_add(lock_owner);
	} else
		lock_owner->cli_next_seq++;

	if (!lock_of) {
		lock_of = openfile_new(nst_lock, lock_owner);
		if (!lock_of) {
			status = NFS4ERR_RESOURCE;
			goto err_out;
		}

		new_lock_of = true;

		lock_of->inum = ino->inum;
		lock_of->lock_open = of;

		list_add(&lock_of->inode_node, &ino_openfile_list);
		list_add(&lock_of->owner_node, &lock_owner->openfiles);
		g_hash_table_insert(srv.openfiles,
				    GUINT_TO_POINTER(lock_of->id),
				    lock_of);
	} else
		lock_of->my_seq++;

	list_add_tail(&lock_ent->node, &lock_of->lock_list);

	sid = &tmp_sid;
	sid->seqid = lock_of->my_seq;
	sid->id = lock_of->id;
	memcpy(&sid->server_verf, &srv.instance_verf, 4);
	memcpy(&sid->server_magic, SRV_MAGIC, 4);

	status = NFS4_OK;

	if (debugging)
		applog(LOG_INFO, "   LOCK -> (SEQ:%u ID:%x)",
		       sid->seqid, lock_of->id);

out:
	if (conflict) {
		WR32(NFS4ERR_DENIED);
		WR64(offset);		/* offset */
		WR64(length);		/* length */
		WR32(locktype);		/* lock type */
		WR64(conflict->cli);	/* owner id */
		WRSTR(conflict->owner);	/* owner name */
	} else {
		WR32(status);
		if (status == NFS4_OK)
			WRSID(sid);
	}
	inode_free(ino);
	return status;

err_out:
	free(lock_ent);
	goto out;
}

nfsstat4 nfs_op_unlock(struct nfs_cxn *cxn, const LOCKU4args *args,
		       struct list_head *writes, struct rpc_write **wr)
{
	nfsstat4 status = NFS4_OK;
	struct nfs_stateid sid;
	struct nfs_inode *ino = NULL;
	nfs_lock_type4 locktype;
	uint32_t seqid;
	uint64_t offset, length;
	struct nfs_lock *lock_ent, *iter;
	struct nfs_openfile *lock_of;

	/* indicate this RPC message should be cached in DRC */
	cxn->drc_mask |= drc_unlock;

	/* read LOCKU arguments */
	locktype = args->locktype;
	seqid = args->seqid;
	copy_sid(&sid, &args->lock_stateid);
	offset = args->offset;
	length = args->length;

	if (debugging)
		applog(LOG_INFO, "op UNLOCK (TYP:%s SEQ:%u OFS:%Lu LEN:%Lx "
		       "IDSEQ:%u ID:%x)",
		       name_lock_type4[locktype],
		       seqid,
		       (unsigned long long) offset,
		       (unsigned long long) length,
		       sid.seqid,
		       sid.id);

	/* validate length and offset+length */
	if (!length || ((length != ~0ULL) &&
		     ((uint64_t)length > ~(uint64_t)offset))) {
		status = NFS4ERR_INVAL;
		goto out;
	}

	/* grab and validate inode */
	ino = inode_fhdec(NULL, cxn->current_fh, 0);
	if (!ino) {
		status = NFS4ERR_NOFILEHANDLE;
		goto out;
	}

	/* we only support reading from regular files */
	if (ino->type != NF4REG) {
		if (debugging)
			applog(LOG_INFO, "trying to lock file of type %s",
			       name_nfs_ftype4[ino->type]);
		if (ino->type == NF4DIR)
			status = NFS4ERR_ISDIR;
		else
			status = NFS4ERR_INVAL;
		goto out;
	}

	/* obtain lock-openfile and lock_owner via stateid lookup */
	status = openfile_lookup(&sid, ino, nst_lock, &lock_of);
	if (status != NFS4_OK)
		goto out;

	if (seqid != lock_of->owner->cli_next_seq) {
		status = NFS4ERR_BAD_SEQID;
		goto out;
	}

	/* delete the first matching lock range, on lock openfile's list */
	status = NFS4ERR_LOCK_RANGE;
	list_for_each_entry_safe(lock_ent, iter, &lock_of->lock_list, node) {
		if (offset != lock_ent->ofs || length != lock_ent->len)
			continue;

		list_del(&lock_ent->node);
		free(lock_ent);
		status = NFS4_OK;
		break;
	}

	/* if successful, increment seqids */
	if (status == NFS4_OK) {
		lock_of->my_seq++;
		lock_of->owner->cli_next_seq++;

		sid.seqid = lock_of->my_seq;
	}

	if (debugging)
		applog(LOG_INFO, "   UNLOCK -> (SEQ:%u ID:%x)",
		       sid.seqid, sid.id);

out:
	WR32(status);
	if (status == NFS4_OK)
		WRSID(&sid);
	inode_free(ino);
	return status;
}

