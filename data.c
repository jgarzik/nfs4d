
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
	uint64_t offset;
	uint32_t count;

	/* read COMMIT args */
	offset = CR64();
	count = CR32();

	if (debugging)
		syslog(LOG_INFO, "op COMMIT (OFS:%Lu LEN:%x)",
		       (unsigned long long) offset, count);

	/* obtain and validate inode */
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

	/* validate offset+count */
	if ((uint64_t) count > ~(uint64_t)offset) {
		status = NFS4ERR_INVAL;
		goto out;
	}

	/* since this is a RAM-based server, we do nothing else.
	 * everything is already committed.
	 */

out:
	WR32(status);
	if (status == NFS4_OK)
		WRMEM(&srv.instance_verf, sizeof(srv.instance_verf));
	return status;
}

static GList *inode_data_ofs(struct nfs_inode *ino, uint64_t ofs,
			     unsigned int *ofs_in_buf)
{
	GList *tmp;
	struct refbuf *rb;

	if (G_UNLIKELY(!ino || ino->type != NF4REG))
		return NULL;

	tmp = ino->buf_list;
	while (tmp) {
		rb = tmp->data;

		if (ofs < rb->len)
			break;

		ofs -= rb->len;

		tmp = tmp->next;
	}

	*ofs_in_buf = ofs;
	return tmp;
}

nfsstat4 nfs_op_write(struct nfs_cxn *cxn, struct curbuf *cur,
		      struct list_head *writes, struct rpc_write **wr)
{
	nfsstat4 status = NFS4_OK;
	struct nfs_stateid sid;
	struct nfs_inode *ino;
	uint64_t new_size, offset;
	uint32_t stable;
	struct nfs_buf data;
	struct nfs_access ac = { NULL, };
	uint64_t old_size, size_exist = 0, size_skip = 0, size_after = 0;
	struct refbuf *zero_rb = NULL, *append_rb = NULL;

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

	/*
	 * calculate the sizes of various regions we must deal
	 * with: existing data region (may be overwritten),
	 * zero-filled region that exists if offset is beyond EOF,
	 * and the region that follows if data is being appended.
	 *
	 * Perform all allocations (and check for failure), before
	 * overwriting any data.
	 */

	new_size = offset + data.len;
	if (new_size < old_size)
		new_size = old_size;

	if (offset < old_size)
		size_exist = MIN(data.len, old_size - offset);

	if (offset > old_size) {
		size_skip = offset - old_size;
		zero_rb = refbuf_new(size_skip, true);
		if (!zero_rb) {
			status = NFS4ERR_NOSPC;
			goto out;
		}
	}

	if (new_size > old_size) {
		size_after = new_size - old_size - size_skip;
		append_rb = refbuf_new(size_after, false);
		if (!append_rb) {
			status = NFS4ERR_NOSPC;
			goto out;
		}
		memcpy(append_rb->buf,
		       data.val + (data.len - size_after), size_after);
	}

	/* overwrite portion of existing-data region */
	if (size_exist) {
		unsigned int i, buf_ofs = 0;
		GList *tmp;
		struct refbuf *rb;
		void *buf = data.val;

		tmp = inode_data_ofs(ino, offset, &buf_ofs);
		rb = tmp->data;
		i = MIN(size_exist, rb->len - buf_ofs);
		memcpy(rb->buf + buf_ofs, buf, i);

		buf += i;
		size_exist -= i;
		tmp = tmp->next;

		while (size_exist) {
			rb = tmp->data;
			i = MIN(size_exist, rb->len);
			memcpy(rb->buf, buf, i);

			buf += i;
			size_exist -= i;
			tmp = tmp->next;
		}
	}

	/* store zero-filled region */
	if (zero_rb)
		ino->buf_list = g_list_append(ino->buf_list, zero_rb);

	/* store data in appended-data region */
	if (append_rb)
		ino->buf_list = g_list_append(ino->buf_list, append_rb);

	ino->size = new_size;

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
	struct nfs_inode *ino;
	uint64_t read_size = 0, offset, tmp_read_size, pad_size;
	uint32_t count;
	bool eof = false;
	struct nfs_access ac = { NULL, };
	struct refbuf *rb;
	GList *tmp, *buf_list = NULL;
	unsigned int buf_ofs = 0;
	struct rpc_write *tmp_wr, *final_wr = NULL, *pad_wr = NULL;

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

	ino = inode_get(cxn->current_fh);
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

	tmp_read_size = read_size;
	tmp = inode_data_ofs(ino, offset, &buf_ofs);
	while (tmp_read_size) {
		unsigned int i;

		rb = tmp->data;
		i = MIN(tmp_read_size, rb->len - buf_ofs);

		tmp_wr = wr_ref(rb, buf_ofs, i);
		if (!tmp_wr) {
			status = NFS4ERR_RESOURCE;
			goto err_out;
		}

		buf_list = g_list_append(buf_list, tmp_wr);

		buf_ofs = 0;
		tmp_read_size -= i;
		tmp = tmp->next;
	}

	final_wr = wr_alloc(0);
	if (!final_wr) {
		status = NFS4ERR_RESOURCE;
		goto err_out;
	}

	pad_size = (XDR_QUADLEN(read_size) * 4) - read_size;
	if (pad_size) {
		pad_wr = wr_ref(&pad_rb, 0, pad_size);
		if (!pad_wr) {
			status = NFS4ERR_RESOURCE;
			goto err_out_final;
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
			tmp = buf_list;
			while (tmp) {
				tmp_wr = tmp->data;
				list_add_tail(&tmp_wr->node, writes);
				tmp = tmp->next;
			}

			g_list_free(buf_list);

			list_add_tail(&final_wr->node, writes);

			if (pad_wr) {
				list_add_tail(&pad_wr->node, writes);
				final_wr = pad_wr;
			}

			*wr = final_wr;
		}
	}
	return status;

err_out_final:
	wr_unref(final_wr);
err_out:
	tmp = buf_list;
	while (tmp) {
		tmp_wr = tmp->data;
		wr_unref(tmp_wr);
		tmp = tmp->next;
	}
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
		status = openfile_lookup(prev_sid, ino, nst_open, &of);
		if (status != NFS4_OK)
			goto out;

		if (open_seqid != of->cli_next_seq) {
			status = NFS4ERR_BAD_SEQID;
			goto out;
		}

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

		if (lock_seqid != lock_of->cli_next_seq) {
			status = NFS4ERR_BAD_SEQID;
			goto out;
		}

		of = lock_of->u.lock.open;
	}

	of->cli_next_seq++;

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

		cli_owner_add(lock_owner);
	}

	if (!lock_of) {
		lock_of = openfile_new(nst_lock, lock_owner);
		if (!lock_of) {
			status = NFS4ERR_RESOURCE;
			goto err_out;
		}

		new_lock_of = true;

		lock_of->ino = ino->ino;
		lock_of->generation = ino->generation;
		lock_of->cli_next_seq = lock_seqid + 1;
		lock_of->u.lock.open = of;

		list_add(&lock_of->inode_node, &ino->openfile_list);
		list_add(&lock_of->owner_node, &lock_owner->openfiles);
		g_hash_table_insert(srv.openfiles,
				    GUINT_TO_POINTER(lock_of->id),
				    lock_of);
	} else {
		lock_of->my_seq++;
		lock_of->cli_next_seq++;
	}

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

	/* obtain lock-openfile and lock_owner via stateid lookup */
	status = openfile_lookup(&sid, ino, nst_lock, &lock_of);
	if (status != NFS4_OK)
		goto out;

	if (seqid != lock_of->cli_next_seq) {
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
		lock_of->cli_next_seq++;

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

	/* validate owner */
	if (!owner.len || !owner.val) {
		status = NFS4ERR_BADXDR;
		goto out;
	}

	/* at the moment, we do nothing other than the minimum:
	 * return NFS4ERR_LOCKS_HELD or NFS4_OK as specified
	 */
	if (cli_locks_held(id, &owner))
		status = NFS4ERR_LOCKS_HELD;

out:
	WR32(status);
	return status;
}

