
#define _GNU_SOURCE
#include <string.h>
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
	struct nfs_inode *ino;
	uint64_t offset = CR64();
	uint32_t count = CR32();

	if (debugging)
		syslog(LOG_INFO, "op COMMIT (OFS:%Lu LEN:%x)",
		       (unsigned long long) offset, count);

	ino = inode_get(cxn->current_fh);
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

	if ((uint64_t) count > ~(uint64_t)offset) {
		status = NFS4ERR_INVAL;
		goto out;
	}

out:
	WR32(status);
	if (status == NFS4_OK)
		WRMEM(&srv.instance_verf, sizeof(srv.instance_verf));
	return status;
}

nfsstat4 nfs_op_write(struct nfs_cxn *cxn, struct curbuf *cur,
		      struct list_head *writes, struct rpc_write **wr)
{
	nfsstat4 status = NFS4_OK;
	struct nfs_stateid sid;
	struct nfs_state *st = NULL;
	struct nfs_inode *ino;
	uint64_t new_size, offset;
	uint32_t stable;
	void *mem;
	struct nfs_buf data;

	if (cur->len < 32) {
		status = NFS4ERR_BADXDR;
		goto out;
	}

	CURSID(&sid);
	offset = CR64();
	stable = CR32();
	CURBUF(&data);

	if (debugging)
		syslog(LOG_INFO, "op WRITE (IDSEQ:%u ID:%x OFS:%Lu ST:%s LEN:%x)",
		       sid.seqid, sid.id,
		       (unsigned long long) offset,
		       name_stable_how4[stable],
		       data.len);

	if (data.len > SRV_MAX_WRITE)
		data.len = SRV_MAX_WRITE;

	ino = inode_get(cxn->current_fh);
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

	status = access_ok(&sid, ino->ino, true, offset, data.len, &st, NULL);
	if (status != NFS4_OK)
		goto out;

	if (data.len == 0)
		goto out;

	new_size = offset + data.len;

	/* write fits entirely within existing data buffer */
	if (new_size <= ino->size)
		memcpy(ino->data + offset, data.val, data.len);

	/* new size is larger than old size, enlarge buffer */
	else {
		uint64_t old_size = ino->size;

		mem = realloc(ino->data, new_size);
		if (!mem) {
			status = NFS4ERR_NOSPC;
			goto out;
		}

		ino->data = mem;
		ino->size = new_size;

		memcpy(ino->data + offset, data.val, data.len);

		srv.space_used += (new_size - old_size);
	}

out:
	WR32(status);
	if (status == NFS4_OK) {
		WR32(data.len);
		WR32(FILE_SYNC4);
		WRMEM(&srv.instance_verf, sizeof(verifier4));
	}
	return status;
}

nfsstat4 nfs_op_read(struct nfs_cxn *cxn, struct curbuf *cur,
		     struct list_head *writes, struct rpc_write **wr)
{
	nfsstat4 status = NFS4_OK;
	struct nfs_stateid sid;
	struct nfs_state *st = NULL;
	struct nfs_inode *ino;
	uint64_t read_size = 0, offset;
	uint32_t count;
	void *mem;
	bool eof = false;

	if (cur->len < 28) {
		status = NFS4ERR_BADXDR;
		goto out;
	}

	CURSID(&sid);
	offset = CR64();
	count = CR32();

	if (debugging)
		syslog(LOG_INFO, "op READ (IDSEQ:%u ID:%x OFS:%Lu LEN:%x)",
		       sid.seqid, sid.id,
		       (unsigned long long) offset, count);

	if (count > SRV_MAX_READ)
		count = SRV_MAX_READ;

	mem = malloc(count);
	if (!mem) {
		status = NFS4ERR_RESOURCE;
		goto out;
	}
	memset(mem, 0, count);

	ino = inode_get(cxn->current_fh);
	if (!ino) {
		status = NFS4ERR_NOFILEHANDLE;
		goto out_mem;
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
		goto out_mem;
	}

	status = access_ok(&sid, ino->ino, false, offset, count, &st, NULL);
	if (status != NFS4_OK)
		goto out;

	if (offset >= ino->size) {
		eof = true;
		goto out_mem;
	}
	if (count == 0)
		goto out_mem;

	read_size = ino->size - offset;
	if (read_size > count)
		read_size = count;

	memcpy(mem, ino->data + offset, read_size);

	if ((offset + read_size) >= ino->size)
		eof = true;

out:
	WR32(status);
	if (status == NFS4_OK) {
		struct nfs_buf nb = { read_size, mem };
		WR32(eof);
		WRBUF(&nb);
	}
	return status;

out_mem:
	free(mem);
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
	struct nfs_state *match = NULL;

	if (cur->len < 28) {
		status = NFS4ERR_BADXDR;
		goto out;
	}

	locktype = CR32();
	offset = CR64();
	length = CR64();
	owner_id = CR64();
	CURBUF(&owner);

	if (debugging)
		syslog(LOG_INFO, "op TESTLOCK (TYP:%s OFS:%Lu LEN:%Lx)",
		       name_lock_type4[locktype],
		       (unsigned long long) offset,
		       (unsigned long long) length);

	if (!length || ((length != ~0ULL) &&
		     ((uint64_t)length > ~(uint64_t)offset))) {
		status = NFS4ERR_INVAL;
		goto out;
	}

	ino = inode_get(cxn->current_fh);
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

	status = access_ok(NULL, ino->ino, 
			   (locktype == READ_LT || locktype == READW_LT) ?
			   	false : true,
			   offset, length, NULL, &match);

out:
	if (match) {
		WR32(NFS4ERR_DENIED);
		WR64(offset);		/* offset */
		WR64(length);		/* length */
		WR32(locktype);		/* lock type */
		WR64(match->cli);	/* owner id */
		WRSTR(match->owner);	/* owner name */
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
	struct nfs_state *st;
	struct nfs_stateid *prev_sid;
	uint32_t prev_id;
	struct nfs_stateid *sid, lock_sid, open_sid, tmp_sid;
	bool reclaim, new_lock;
	uint32_t locktype, lock_seqid, open_seqid = 0;
	uint64_t offset, length, id_short = 0;
	struct nfs_buf owner;
	struct nfs_lock *lock_ent;
	struct nfs_state *open_st = NULL, *conflict = NULL;

	if (cur->len < 28) {
		status = NFS4ERR_BADXDR;
		goto out;
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

	ino = inode_get(cxn->current_fh);
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
		status = stateid_lookup(prev_id, ino->ino, nst_open, &open_st);
		if (status != NFS4_OK)
			goto out;

		if (open_seqid != open_st->seq) {
			status = NFS4ERR_BAD_SEQID;
			goto out;
		}

		if ((locktype == WRITE_LT || locktype == WRITEW_LT) &&
		    (open_st->u.share.access == OPEN4_SHARE_ACCESS_READ)) {
			status = NFS4ERR_OPENMODE;
			goto out;
		}
	} else {
		struct nfs_state *lock_st = NULL;

		status = stateid_lookup(prev_id, ino->ino, nst_lock, &lock_st);
		if (status != NFS4_OK)
			goto out;

		if (lock_seqid != lock_st->seq) {
			status = NFS4ERR_BAD_SEQID;
			goto out;
		}
	}

	status = access_ok(prev_sid, ino->ino,
		(locktype == READ_LT || locktype == READW_LT) ? false : true,
		offset, length, NULL, &conflict);
	if (conflict)
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
	 * update lock state
	 */

	if (!new_lock) {
		/* FIXME? */
	}

	/*
	 * otherwise, create new lock state
	 */
	else {

		/*
	 	* look up shorthand client id (clientid4) for new lock owner
	 	*/
		status = clientid_test(id_short);
		if (status != NFS4_OK)
			goto out;

		st = state_new(nst_lock, &owner);
		if (!st) {
			status = NFS4ERR_RESOURCE;
			goto out;
		}

		st->cli = id_short;
		st->ino = ino->ino;
		st->u.lock.open = open_st;

		g_hash_table_insert(srv.state, GUINT_TO_POINTER(st->id), st);
	}

	list_add_tail(&lock_ent->node, &st->u.lock.list);

	st->seq = lock_seqid + 1;

	sid = &tmp_sid;
	sid->seqid = lock_seqid;
	sid->id = st->id;
	memcpy(&sid->server_verf, &srv.instance_verf,
	       sizeof(srv.instance_verf));

	status = NFS4_OK;

	if (debugging)
		syslog(LOG_INFO, "   LOCK -> (SEQ:%u ID:%x)",
		       sid->seqid, st->id);

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
}

nfsstat4 nfs_op_unlock(struct nfs_cxn *cxn, struct curbuf *cur,
		       struct list_head *writes, struct rpc_write **wr)
{
	nfsstat4 status = NFS4_OK;
	struct nfs_stateid sid;
	struct nfs_state *st = NULL;
	struct nfs_inode *ino;
	uint32_t locktype, seqid;
	uint64_t offset, length;
	struct nfs_lock *lock_ent, *iter;

	if (cur->len < 40) {
		status = NFS4ERR_BADXDR;
		goto out;
	}

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

	if (!length || ((length != ~0ULL) &&
		     ((uint64_t)length > ~(uint64_t)offset))) {
		status = NFS4ERR_INVAL;
		goto out;
	}

	ino = inode_get(cxn->current_fh);
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

	status = stateid_lookup(sid.id, ino->ino, nst_lock, &st);
	if (status != NFS4_OK)
		goto out;

	if (seqid != st->seq) {
		status = NFS4ERR_BAD_SEQID;
		goto out;
	}

	/* FIXME SECURITY: make sure we are the lock owner????? */

	status = NFS4ERR_LOCK_RANGE;
	list_for_each_entry_safe(lock_ent, iter, &st->u.lock.list, node) {
		if (offset != lock_ent->ofs || length != lock_ent->len)
			continue;

		list_del(&lock_ent->node);
		free(lock_ent);
		status = NFS4_OK;
		break;
	}

	if (list_empty(&st->u.lock.list))
		state_trash(st);

out:
	WR32(status);
	if (status == NFS4_OK)
		WRSID(&sid);
	return status;
}

