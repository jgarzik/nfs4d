
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

struct state_search {
	bool			match;
	nfsino_t		ino;
	uint32_t		share_dn;
	struct nfs_state	*st;
};

static void state_search_iter(gpointer key, gpointer val, gpointer user_data)
{
	struct nfs_state *st = val;
	struct state_search *ss = user_data;

	if ((st->ino == ss->ino) && (st->share_dn & ss->share_dn) &&
	    (!(st->flags & stfl_lock))) {
		ss->match = true;
		ss->st = st;
	}
}

bool nfs_op_commit(struct nfs_cxn *cxn, COMMIT4args *arg, COMPOUND4res *cres)
{
	struct nfs_resop4 resop;
	COMMIT4res *res;
	COMMIT4resok *resok;
	nfsstat4 status = NFS4_OK;
	struct nfs_inode *ino;

	memset(&resop, 0, sizeof(resop));
	resop.resop = OP_COMMIT;
	res = &resop.nfs_resop4_u.opcommit;
	resok = &res->COMMIT4res_u.resok4;

	if (debugging)
		syslog(LOG_INFO, "op COMMIT (OFS:%Lu LEN:%x)",
		       (unsigned long long) arg->offset,
		       arg->count);

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

	if ((uint64_t) arg->count > ~(uint64_t)arg->offset) {
		status = NFS4ERR_INVAL;
		goto out;
	}

	memcpy(&resok->writeverf, srv.instance_verf, sizeof(srv.instance_verf));

out:
	res->status = status;
	return push_resop(cres, &resop, status);
}

bool nfs_op_write(struct nfs_cxn *cxn, WRITE4args *arg, COMPOUND4res *cres)
{
	struct nfs_resop4 resop;
	WRITE4res *res;
	WRITE4resok *resok;
	nfsstat4 status = NFS4_OK;
	struct nfs_stateid *sid = (struct nfs_stateid *) &arg->stateid;
	uint32_t id = GUINT32_FROM_LE(sid->id);
	struct nfs_state *st = NULL;
	struct nfs_inode *ino;
	uint64_t new_size;
	void *mem;
	struct state_search ss;
	unsigned int data_len = arg->data.data_len;

	if (debugging)
		syslog(LOG_INFO, "op WRITE (IDSEQ:%u ID:%x OFS:%Lu ST:%s LEN:%x)",
		       arg->stateid.seqid, id,
		       (unsigned long long) arg->offset,
		       name_stable_how4[arg->stable],
		       data_len);

	memset(&resop, 0, sizeof(resop));
	resop.resop = OP_WRITE;
	res = &resop.nfs_resop4_u.opwrite;
	resok = &res->WRITE4res_u.resok4;

	if (data_len > SRV_MAX_WRITE)
		data_len = SRV_MAX_WRITE;

	if (id && (id != 0xffffffffU)) {
		status = stateid_lookup(id, &st);
		if (status != NFS4_OK)
			goto out;

		if (!(st->share_ac & OPEN4_SHARE_ACCESS_WRITE)) {
			status = NFS4ERR_OPENMODE;
			goto out;
		}
	}

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

	/* search for conflicting share reservation (deny write) */
	ss.match = false;
	ss.ino = ino->ino;
	ss.share_dn = OPEN4_SHARE_DENY_WRITE;

	g_hash_table_foreach(srv.state, state_search_iter, &ss);

	if ((ss.match) && (st != ss.st)) {
		status = NFS4ERR_LOCKED;
		goto out;
	}

	if (data_len == 0)
		goto out;

	new_size = arg->offset + data_len;

	/* write fits entirely within existing data buffer */
	if (new_size <= ino->size) {
		memcpy(ino->data + arg->offset, arg->data.data_val, data_len);
	}

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

		memcpy(ino->data + arg->offset, arg->data.data_val, data_len);

		srv.space_used += (new_size - old_size);
	}

	resok->count = data_len;
	resok->committed = FILE_SYNC4;

	/* FIXME: write verifier */

out:
	res->status = status;
	return push_resop(cres, &resop, status);
}

bool nfs_op_read(struct nfs_cxn *cxn, READ4args *arg, COMPOUND4res *cres)
{
	struct nfs_resop4 resop;
	READ4res *res;
	READ4resok *resok;
	nfsstat4 status = NFS4_OK;
	struct nfs_stateid *sid = (struct nfs_stateid *) &arg->stateid;
	uint32_t id = GUINT32_FROM_LE(sid->id);
	struct nfs_state *st = NULL;
	struct nfs_inode *ino;
	uint64_t read_size;
	void *mem;
	struct state_search ss;

	if (debugging)
		syslog(LOG_INFO, "op READ (IDSEQ:%u ID:%x OFS:%Lu LEN:%x)",
		       arg->stateid.seqid, id,
		       (unsigned long long) arg->offset,
		       arg->count);

	memset(&resop, 0, sizeof(resop));
	resop.resop = OP_READ;
	res = &resop.nfs_resop4_u.opread;
	resok = &res->READ4res_u.resok4;

	if (arg->count > SRV_MAX_READ)
		arg->count = SRV_MAX_READ;

	mem = malloc(arg->count);
	if (!mem) {
		status = NFS4ERR_RESOURCE;
		goto out;
	}
	memset(mem, 0, arg->count);

	if (id && (id != 0xffffffffU)) {
		status = stateid_lookup(id, &st);
		if (status != NFS4_OK)
			goto out;

		if (!(st->share_ac & OPEN4_SHARE_ACCESS_READ)) {
			status = NFS4ERR_OPENMODE;
			goto out;
		}
	}

	ino = inode_get(cxn->current_fh);
	if (!ino) {
		status = NFS4ERR_NOFILEHANDLE;
		goto out_mem;
	}

	/* we only support reading from regular files */
	if (ino->type != NF4REG) {
		syslog(LOG_INFO, "trying to read to file of type %s",
		       name_nfs_ftype4[ino->type]);
		if (ino->type == NF4DIR)
			status = NFS4ERR_ISDIR;
		else
			status = NFS4ERR_INVAL;
		goto out_mem;
	}

	/* search for conflicting share reservation (deny read) */
	ss.match = false;
	ss.ino = ino->ino;
	ss.share_dn = OPEN4_SHARE_DENY_READ;

	g_hash_table_foreach(srv.state, state_search_iter, &ss);

	if ((ss.match) && (st != ss.st)) {
		status = NFS4ERR_LOCKED;
		goto out;
	}

	if (arg->offset >= ino->size) {
		resok->eof = true;
		goto out_mem;
	}
	if (arg->count == 0)
		goto out_mem;

	read_size = ino->size - arg->offset;
	if (read_size > arg->count)
		read_size = arg->count;

	memcpy(mem, ino->data + arg->offset, read_size);

	resok->data.data_val = mem;
	resok->data.data_len = read_size;
	if ((arg->offset + read_size) >= ino->size)
		resok->eof = true;

out:
	res->status = status;
	return push_resop(cres, &resop, status);

out_mem:
	free(mem);
	goto out;
}

static bool ranges_intersect(uint64_t a_ofs, uint64_t a_len,
			     uint64_t b_ofs, uint64_t b_len)
{
	if (a_ofs < b_ofs) {
		if ((a_ofs + a_len) < b_ofs)
			return false;
	} else {
		if ((b_ofs + b_len) < a_ofs)
			return false;
	}

	return true;
}

struct state_search_lock {
	nfsino_t ino;
	nfs_lock_type4 type;
	offset4 ofs;
	length4 len;

	GList *list;
};

static void state_search_lock(gpointer key, gpointer val, gpointer user_data)
{
	struct nfs_state *st = val;
	struct state_search_lock *ss = user_data;

	if (st->ino != ss->ino)
		return;
	if (!(st->flags & stfl_lock))
		return;

	if (!ranges_intersect(st->lock_ofs, st->lock_len, ss->ofs, ss->len))
		return;

	if (st->locktype != ss->type)
		return;

	ss->list = g_list_append(ss->list, st);
}

static void find_locks(nfsino_t ino, nfs_lock_type4 type, offset4 ofs,
		       length4 len, GList **list_out)
{
	struct state_search_lock ss = { ino, type, ofs, len };

	g_hash_table_foreach(srv.state, state_search_lock, &ss);

	*list_out = ss.list;
}

static void fill_lock_denied(LOCK4denied *denied, GList *locks)
{
	GList *tmp = locks;
	struct nfs_state *st;

	while (tmp) {
		st = tmp->data;

		denied->offset = st->lock_ofs;
		denied->length = st->lock_len;
		denied->locktype = st->locktype;

		/* FIXME: fill in lock_owner */

		tmp = tmp->next;
	}
}

bool nfs_op_testlock(struct nfs_cxn *cxn, LOCKT4args *arg, COMPOUND4res *cres)
{
	struct nfs_resop4 resop;
	LOCKT4res *res;
	nfsstat4 status = NFS4_OK;
	GList *locks = NULL;
	struct nfs_inode *ino;

	if (debugging)
		syslog(LOG_INFO, "op TESTLOCK (TYP:%s OFS:%Lu LEN:%Lx)",
		       name_lock_type4[arg->locktype],
		       (unsigned long long) arg->offset,
		       (unsigned long long) arg->length);

	memset(&resop, 0, sizeof(resop));
	resop.resop = OP_LOCKT;
	res = &resop.nfs_resop4_u.oplockt;

	if (!arg->length || ((arg->length != ~0ULL) &&
		     ((uint64_t)arg->length > ~(uint64_t)arg->offset))) {
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

	find_locks(ino->ino, arg->locktype, arg->offset, arg->length, &locks);

	if (locks == NULL)
		goto out;

	fill_lock_denied(&res->LOCKT4res_u.denied, locks);

	g_list_free(locks);

	status = NFS4ERR_DENIED;

out:
	res->status = status;
	return push_resop(cres, &resop, status);
}

static void print_lock_args(LOCK4args *arg, uint32_t prev_id_seq,
			    uint32_t prev_id)
{
	bool new_lock;
	uint32_t lseqid;

	if (!debugging)
		return;

	new_lock = arg->locker.new_lock_owner;

	if (new_lock)
		lseqid = arg->locker.locker4_u.open_owner.lock_seqid;
	else
		lseqid = arg->locker.locker4_u.lock_owner.lock_seqid;

	syslog(LOG_INFO, "op LOCK (NEW:%s LSEQ:%u TYP:%s REC:%s OFS:%Lu LEN:%Lx)",
	       new_lock ? "Y" : "N",
	       lseqid,
	       name_lock_type4[arg->locktype],
	       arg->reclaim ? "Y" : "N",
	       (unsigned long long) arg->offset,
	       (unsigned long long) arg->length);

	if (new_lock) {
		syslog(LOG_INFO, "   LOCK (OSEQ:%u IDSEQ:%u ID:%x OCID:%Lx OWNER:%.*s)",
		       arg->locker.locker4_u.open_owner.open_seqid,
		       prev_id_seq, prev_id,
		       (unsigned long long) arg->locker.locker4_u.open_owner.lock_owner.clientid,
		       arg->locker.locker4_u.open_owner.lock_owner.owner.owner_len,
		       arg->locker.locker4_u.open_owner.lock_owner.owner.owner_val);
	} else {
		syslog(LOG_INFO, "   LOCK (IDSEQ:%u ID:%x)",
		       prev_id_seq, prev_id);
	}
}

bool nfs_op_lock(struct nfs_cxn *cxn, LOCK4args *arg, COMPOUND4res *cres)
{
	struct nfs_resop4 resop;
	LOCK4res *res;
	LOCK4resok *resok;
	nfsstat4 status = NFS4_OK;
	struct nfs_inode *ino;
	struct nfs_state *st;
	struct nfs_state *prev_st = NULL;
	struct nfs_stateid *prev_sid;
	uint32_t prev_id;
	struct nfs_stateid *sid;
	GList *locks = NULL;
	uint32_t lseqid;
	bool new_lock = arg->locker.new_lock_owner;

	if (new_lock) {
		lseqid = arg->locker.locker4_u.open_owner.lock_seqid;

		prev_sid = (struct nfs_stateid *)
			&arg->locker.locker4_u.open_owner.open_stateid;
	} else {
		lseqid = arg->locker.locker4_u.lock_owner.lock_seqid;

		prev_sid = (struct nfs_stateid *)
			&arg->locker.locker4_u.lock_owner.lock_stateid;
	}

	prev_id = GUINT32_FROM_LE(prev_sid->id);

	print_lock_args(arg, prev_sid->seqid, prev_id);

	memset(&resop, 0, sizeof(resop));
	resop.resop = OP_LOCK;
	res = &resop.nfs_resop4_u.oplock;
	resok = &res->LOCK4res_u.resok4;

	if (!arg->length || ((arg->length != ~0ULL) &&
		     ((uint64_t)arg->length > ~(uint64_t)arg->offset))) {
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

	status = stateid_lookup(prev_id, &prev_st);
	if (status != NFS4_OK)
		goto out;

	if (new_lock) {
		if (arg->locker.locker4_u.open_owner.open_seqid !=
			prev_st->seq) {
			status = NFS4ERR_BAD_SEQID;
			goto out;
		}

		if ((arg->locktype == WRITE_LT || arg->locktype == WRITEW_LT) &&
		    (prev_st->share_ac == OPEN4_SHARE_ACCESS_READ)) {
			status = NFS4ERR_OPENMODE;
			goto out;
		}
	} else {
		if (arg->locker.locker4_u.lock_owner.lock_seqid !=
			prev_st->seq) {
			status = NFS4ERR_BAD_SEQID;
			goto out;
		}
	}

	find_locks(ino->ino, arg->locktype, arg->offset, arg->length, &locks);

	/*
	 * lock update code path...
	 */

	if (!new_lock) {
		/* no locks found? bad user input */
		if (!locks) {
			status = NFS4ERR_INVAL;
			goto out;
		}

		/* more than one lock found? ditto */
		if (locks->next) {
			status = NFS4ERR_INVAL;
			goto out;
		}

		/* FIXME convert the lock... */

		st = locks->data;
		g_list_free(locks);

		goto have_st;
	}

	/*
	 * new-lock code path
	 */

	if (locks) {
		fill_lock_denied(&res->LOCK4res_u.denied, locks);
		g_list_free(locks);
		status = NFS4ERR_DENIED;
		goto out;
	}

	/*
	 * look up shorthand client id (clientid4) for new lock owner
	 */
	status = clientid_test(arg->locker.locker4_u.open_owner.lock_owner.clientid);
	if (status != NFS4_OK)
		goto out;

	st = calloc(1, sizeof(struct nfs_state));
	if (!st) {
		status = NFS4ERR_RESOURCE;
		goto out;
	}

	st->cli = arg->locker.locker4_u.open_owner.lock_owner.clientid;
	st->flags = stfl_lock;
	st->id = gen_stateid();
	st->owner =
	  strndup(arg->locker.locker4_u.open_owner.lock_owner.owner.owner_val,
	          arg->locker.locker4_u.open_owner.lock_owner.owner.owner_len);

	st->ino = ino->ino;

	st->locktype = arg->locktype;
	st->lock_ofs = arg->offset;
	st->lock_len = arg->length;

	g_hash_table_insert(srv.state, GUINT_TO_POINTER(st->id), st);

have_st:
	st->seq = lseqid + 1;

	sid = (struct nfs_stateid *) &resok->lock_stateid;
	sid->seqid = lseqid;
	sid->id = GUINT32_TO_LE(st->id);
	memcpy(&sid->server_verf, &srv.instance_verf,
	       sizeof(srv.instance_verf));

	status = NFS4_OK;

	if (debugging)
		syslog(LOG_INFO, "   LOCK -> (SEQ:%u ID:%x)",
		       sid->seqid, st->id);

out:
	res->status = status;
	return push_resop(cres, &resop, status);
}

bool nfs_op_unlock(struct nfs_cxn *cxn, LOCKU4args *arg, COMPOUND4res *cres)
{
	struct nfs_resop4 resop;
	LOCKU4res *res;
	nfsstat4 status = NFS4_OK;
	struct nfs_stateid *sid = (struct nfs_stateid *) &arg->lock_stateid;
	uint32_t id = GUINT32_FROM_LE(sid->id);
	struct nfs_state *st = NULL;
	struct nfs_inode *ino;

	memset(&resop, 0, sizeof(resop));
	resop.resop = OP_LOCKU;
	res = &resop.nfs_resop4_u.oplocku;

	if (debugging)
		syslog(LOG_INFO, "op UNLOCK (TYP:%s SEQ:%u OFS:%Lu LEN:%Lx "
		       "IDSEQ:%u ID:%x)",
		       name_lock_type4[arg->locktype],
		       arg->seqid,
		       (unsigned long long) arg->offset,
		       (unsigned long long) arg->length,
		       arg->lock_stateid.seqid,
		       id);

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

	status = stateid_lookup(id, &st);
	if (status != NFS4_OK)
		goto out;

	if (arg->seqid != st->seq) {
		status = NFS4ERR_BAD_SEQID;
		goto out;
	}

	/* FIXME SECURITY: make sure we are the lock owner!!!!! */

	if ((arg->offset != st->lock_ofs) || (arg->length != st->lock_len)) {
		status = NFS4ERR_LOCK_RANGE;
		goto out;
	}

	state_trash(st);

	memcpy(&res->LOCKU4res_u.lock_stateid, &arg->lock_stateid,
	       sizeof(arg->lock_stateid));

out:
	res->status = status;
	return push_resop(cres, &resop, status);
}

