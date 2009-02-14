
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

nfsstat4 nfs_op_commit(struct nfs_cxn *cxn, struct curbuf *cur,
		       struct list_head *writes, struct rpc_write **wr)
{
	nfsstat4 status = NFS4_OK;
	struct nfs_inode *ino = NULL;
	uint64_t offset;
	uint32_t count;
	char *fdpath;
	int fd;

	/* read COMMIT args */
	offset = CR64();
	count = CR32();

	if (debugging)
		syslog(LOG_INFO, "op COMMIT (OFS:%Lu LEN:%x)",
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

	fdpath = alloca(strlen(srv.data_dir) + strlen(ino->dataname) + 1);
	sprintf(fdpath, "%s%s", srv.data_dir, ino->dataname);

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

nfsstat4 nfs_op_write(struct nfs_cxn *cxn, struct curbuf *cur,
		      struct list_head *writes, struct rpc_write **wr)
{
	nfsstat4 status = NFS4_OK;
	struct nfs_stateid sid;
	struct nfs_inode *ino = NULL;
	uint64_t new_size, offset;
	uint32_t stable;
	struct nfs_buf data;
	struct nfs_access ac = { NULL, };
	uint64_t old_size;
	int fd, frc;
	char *fdpath;
	size_t pending;
	void *p;

	if (cur->len < 32) {
		status = NFS4ERR_BADXDR;
		goto out;
	}

	CURSID(&sid);
	offset = CR64();
	stable = CR32();
	CURBUF(&data);

	srv.stats.write_bytes += data.len;

	if (debugging)
		syslog(LOG_INFO, "op WRITE (IDSEQ:%u ID:%x OFS:%Lu ST:%s LEN:%x)",
		       sid.seqid, sid.id,
		       (unsigned long long) offset,
		       name_stable_how4[stable],
		       data.len);

	if (data.len > SRV_MAX_WRITE)
		data.len = SRV_MAX_WRITE;

	ino = inode_fhdec(NULL, cxn->current_fh, 0);
	if (!ino) {
		status = NFS4ERR_NOFILEHANDLE;
		goto out;
	}

	/* we only support writing to regular files */
	if (ino->type != NF4REG) {
		if (debugging)
			syslog(LOG_INFO, "trying to write to file of type %s",
			       name_nfs_ftype4[ino->type]);
		if (ino->type == NF4DIR)
			status = NFS4ERR_ISDIR;
		else
			status = NFS4ERR_INVAL;
		goto out;
	}

	old_size = ino->size;

	ac.sid = &sid;
	ac.ino = ino;
	ac.op = OP_WRITE;
	ac.ofs = offset;
	ac.len = data.len;
	status = access_ok(&ac);
	if (status != NFS4_OK)
		goto out;

	if (data.len == 0)
		goto out;

	new_size = offset + data.len;
	if (new_size < old_size)
		new_size = old_size;

	fdpath = alloca(strlen(srv.data_dir) + strlen(ino->dataname) + 1);
	sprintf(fdpath, "%s%s", srv.data_dir, ino->dataname);
	fd = open(fdpath, O_WRONLY);
	if (fd < 0) {
		syslogerr2("open", fdpath);
		goto err_io;
	}

	if (lseek64(fd, offset, SEEK_SET) < 0) {
		syslogerr2("lseek64", fdpath);
		goto err_io_fd;
	}

	p = data.val;
	pending = data.len;
	while (pending > 0) {
		ssize_t rc = write(fd, p, pending);
		if (rc < 0) {
			syslogerr2("write", fdpath);
			goto err_io_fd;
		}

		pending -= rc;
		p += rc;
	}

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

	if (close(fd) < 0) {
		syslogerr2("close", fdpath);
		goto err_io;
	}

	ino->size = new_size;

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
	goto out;
}

nfsstat4 nfs_op_read(struct nfs_cxn *cxn, struct curbuf *cur,
		     struct list_head *writes, struct rpc_write **wr)
{
	nfsstat4 status = NFS4_OK;
	struct nfs_stateid sid;
	struct nfs_inode *ino = NULL;
	uint64_t read_size = 0, offset, pad_size;
	uint32_t count;
	bool eof = false;
	struct nfs_access ac = { NULL, };
	struct rpc_write *data_wr = NULL, *final_wr = NULL, *pad_wr = NULL;
	int fd;
	char *fdpath;

	if (cur->len < 28) {
		status = NFS4ERR_BADXDR;
		goto out;
	}

	CURSID(&sid);
	offset = CR64();
	count = CR32();

	srv.stats.read_bytes += count;

	if (debugging)
		syslog(LOG_INFO, "op READ (IDSEQ:%u ID:%x OFS:%Lu LEN:%x)",
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
			syslog(LOG_INFO, "trying to read to file of type %s",
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
		goto out;
	}
	if (count == 0)
		goto out;

	read_size = ino->size - offset;
	if (read_size > count)
		read_size = count;
	if (read_size > RPC_WRITE_BUFSZ)
		read_size = RPC_WRITE_BUFSZ;

	final_wr = data_wr = wr_alloc(read_size);
	if (!data_wr) {
		status = NFS4ERR_RESOURCE;
		goto out;
	}

	fdpath = alloca(strlen(srv.data_dir) + strlen(ino->dataname) + 1);
	sprintf(fdpath, "%s%s", srv.data_dir, ino->dataname);
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

	pad_size = (XDR_QUADLEN(read_size) * 4) - read_size;
	if (pad_size) {
		pad_wr = wr_ref(&pad_rb, 0, pad_size);
		if (!pad_wr) {
			status = NFS4ERR_RESOURCE;
			goto err_out_data;
		}

		final_wr = pad_wr;
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
			*wr = final_wr;
		}
	}
	inode_free(ino);
	return status;

err_io_fd:
	close(fd);
err_io:
	status = NFS4ERR_IO;
err_out_data:
	wr_unref(data_wr);
	goto out;
}

nfsstat4 nfs_op_testlock(struct nfs_cxn *cxn, struct curbuf *cur,
		         struct list_head *writes, struct rpc_write **wr)
{
	nfsstat4 status = NFS4_OK;
	struct nfs_inode *ino;
	uint32_t locktype;
	uint64_t offset, length;
	clientid4 owner_id;
	struct nfs_buf owner;
	struct nfs_access ac = { NULL, };
	struct nfs_owner *o = NULL;

	/* easy check for incomplete args (our routines will return
	 * zeroes if overflow occurs, so this is just nice)
	 */
	if (cur->len < 28) {
		WR32(NFS4ERR_BADXDR);
		return NFS4ERR_BADXDR;
	}

	/* read LOCKT args */
	locktype = CR32();
	offset = CR64();
	length = CR64();
	owner_id = CR64();
	CURBUF(&owner);

	if (debugging)
		syslog(LOG_INFO, "op TESTLOCK (TYP:%s OFS:%Lu LEN:%Lx OCID:%Lx OWNER:%.*s)",
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
			syslog(LOG_INFO, "trying to lock file of type %s",
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

	syslog(LOG_INFO, "op LOCK (NEW:%s LSEQ:%u TYP:%s REC:%s OFS:%Lu LEN:%Lx)",
	       new_lock ? "Y" : "N",
	       lseqid,
	       name_lock_type4[locktype],
	       reclaim ? "Y" : "N",
	       (unsigned long long) offset,
	       (unsigned long long) length);

	if (new_lock) {
		syslog(LOG_INFO, "   LOCK (OSEQ:%u IDSEQ:%u ID:%x OCID:%Lx OWNER:%.*s)",
		       open_seqid,
		       prev_id_seq, prev_id,
		       (unsigned long long) id_short,
		       owner->len,
		       owner->val);
	} else {
		syslog(LOG_INFO, "   LOCK (IDSEQ:%u ID:%x)",
		       prev_id_seq, prev_id);
	}
}

nfsstat4 nfs_op_lock(struct nfs_cxn *cxn, struct curbuf *cur,
		     struct list_head *writes, struct rpc_write **wr)
{
	nfsstat4 status = NFS4_OK;
	struct nfs_inode *ino;
	struct nfs_stateid *prev_sid;
	uint32_t prev_id;
	struct nfs_stateid *sid, lock_sid, open_sid, tmp_sid;
	bool reclaim, new_lock, new_lock_of = false;
	uint32_t locktype, lock_seqid, open_seqid = 0;
	uint64_t offset, length, id_short = 0;
	struct nfs_buf owner;
	struct nfs_lock *lock_ent;
	struct nfs_owner *open_owner = NULL, *conflict = NULL;
	struct nfs_owner *lock_owner = NULL;
	struct nfs_openfile *of = NULL, *lock_of = NULL;
	struct nfs_access ac = { NULL, };

	cxn->drc_mask |= drc_lock;

	if (cur->len < 28) {
		WR32(NFS4ERR_BADXDR);
		return NFS4ERR_BADXDR;
	}

	memset(&lock_sid, 0, sizeof(lock_sid));
	memset(&open_sid, 0, sizeof(open_sid));
	memset(&owner, 0, sizeof(owner));

	locktype = CR32();
	reclaim = CR32();
	offset = CR64();
	length = CR64();
	new_lock = CR32();

	if (new_lock) {
		open_seqid = CR32();
		CURSID(&open_sid);
		lock_seqid = CR32();
		id_short = CR64();
		CURBUF(&owner);
	} else {
		CURSID(&lock_sid);
		lock_seqid = CR32();
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
			syslog(LOG_INFO, "trying to lock file of type %s",
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
		    (of->u.share.access == OPEN4_SHARE_ACCESS_READ)) {
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

		of = lock_of->u.lock.open;
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
			goto err_out_lockof;

		lock_owner = owner_new(nst_lock, &owner);
		if (!lock_owner) {
			status = NFS4ERR_RESOURCE;
			goto err_out_lockof;
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
		lock_of->u.lock.open = of;

		list_add(&lock_of->inode_node, &ino_openfile_list);
		list_add(&lock_of->owner_node, &lock_owner->openfiles);
		g_hash_table_insert(srv.openfiles,
				    GUINT_TO_POINTER(lock_of->id),
				    lock_of);
	} else
		lock_of->my_seq++;

	list_add_tail(&lock_ent->node, &lock_of->u.lock.list);

	sid = &tmp_sid;
	sid->seqid = lock_of->my_seq;
	sid->id = lock_of->id;
	memcpy(&sid->server_verf, &srv.instance_verf, 4);
	memcpy(&sid->server_magic, SRV_MAGIC, 4);

	status = NFS4_OK;

	if (debugging)
		syslog(LOG_INFO, "   LOCK -> (SEQ:%u ID:%x)",
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
	return status;

err_out_lockof:
	if (new_lock_of) {
		free(lock_of);
		lock_of = NULL;
	}
err_out:
	free(lock_ent);
	lock_ent = NULL;
	goto out;
}

nfsstat4 nfs_op_unlock(struct nfs_cxn *cxn, struct curbuf *cur,
		       struct list_head *writes, struct rpc_write **wr)
{
	nfsstat4 status = NFS4_OK;
	struct nfs_stateid sid;
	struct nfs_inode *ino;
	uint32_t locktype, seqid;
	uint64_t offset, length;
	struct nfs_lock *lock_ent, *iter;
	struct nfs_openfile *lock_of;

	/* indicate this RPC message should be cached in DRC */
	cxn->drc_mask |= drc_unlock;

	/* easy check for incomplete args (our routines will return
	 * zeroes if overflow occurs, so this is just nice)
	 */
	if (cur->len < 40) {
		status = NFS4ERR_BADXDR;
		goto out;
	}

	/* read LOCKU arguments */
	locktype = CR32();
	seqid = CR32();
	CURSID(&sid);
	offset = CR64();
	length = CR64();

	if (debugging)
		syslog(LOG_INFO, "op UNLOCK (TYP:%s SEQ:%u OFS:%Lu LEN:%Lx "
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
			syslog(LOG_INFO, "trying to lock file of type %s",
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
	list_for_each_entry_safe(lock_ent, iter, &lock_of->u.lock.list, node) {
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
		syslog(LOG_INFO, "   UNLOCK -> (SEQ:%u ID:%x)",
		       sid.seqid, sid.id);

out:
	WR32(status);
	if (status == NFS4_OK)
		WRSID(&sid);
	return status;
}

nfsstat4 nfs_op_release_lockowner(struct nfs_cxn *cxn, struct curbuf *cur,
		       struct list_head *writes, struct rpc_write **wr)
{
	nfsstat4 status = NFS4_OK;
	clientid4 id;
	struct nfs_buf owner;
	struct nfs_owner *o = NULL;
	struct nfs_openfile *tmp_of, *iter;
	bool found = false;

	/* easy check for incomplete args (our routines will return
	 * zeroes if overflow occurs, so this is just nice)
	 */
	if (cur->len < 12) {
		status = NFS4ERR_BADXDR;
		goto out;
	}

	/* read RELEASE_LOCKOWNER arguments */
	id = CR64();
	CURBUF(&owner);

	if (debugging)
		syslog(LOG_INFO, "op RELEASE_LOCKOWNER (OCID:%Lx OWNER:%.*s)",
		       (unsigned long long) id,
		       owner.len,
		       owner.val);

	/* validate owner */
	if (!owner.len || !owner.val) {
		status = NFS4ERR_BADXDR;
		goto out;
	}

	status = owner_lookup_name(id, &owner, &o);
	if (status != NFS4_OK)
		goto out;

	/* we do not support open_owners here */
	if (o->type != nst_lock) {
		status = NFS4ERR_INVAL;
		goto out;
	}

	/* scan for any remaining locks held */
	list_for_each_entry(tmp_of, &o->openfiles, owner_node) {
		if (!list_empty(&tmp_of->u.lock.list))
			found = true;
	}

	if (found) {
		status = NFS4ERR_LOCKS_HELD;
		goto out;
	}

	/* trash all attached [lock] openfiles */
	list_for_each_entry_safe(tmp_of, iter, &o->openfiles, owner_node) {
		openfile_trash(tmp_of, false);
	}

	/* release this lockowner */
	list_del(&o->cli_node);
	owner_free(o);

out:
	WR32(status);
	return status;
}

