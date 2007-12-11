
#include <syslog.h>
#include "server.h"

static const char *name_stable_how4[] = {
	[UNSTABLE4] = "UNSTABLE4",
	[DATA_SYNC4] = "DATA_SYNC4",
	[FILE_SYNC4] = "FILE_SYNC4",
};

struct state_search {
	gboolean match;
	nfsino_t ino;
	uint32_t share_dn;
	struct nfs_state *st;
};

static void state_search_iter(gpointer key, gpointer val, gpointer user_data)
{
	struct nfs_state *st = val;
	struct state_search *ss = user_data;

	if ((st->ino == ss->ino) && (st->share_dn & ss->share_dn)) {
		ss->match = TRUE;
		ss->st = st;
	}
}

bool_t nfs_op_commit(struct nfs_cxn *cxn, COMMIT4args *arg, COMPOUND4res *cres)
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
		syslog(LOG_INFO, "op COMMIT (OFS:%Lu LEN:%u)",
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

bool_t nfs_op_write(struct nfs_cxn *cxn, WRITE4args *arg, COMPOUND4res *cres)
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
		syslog(LOG_INFO, "op WRITE (SEQ:%u ID:%x OFS:%Lu ST:%s LEN:%u)",
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
		syslog(LOG_INFO, "trying to write to file of type %s",
		       name_nfs_ftype4[ino->type]);
		if (ino->type == NF4DIR)
			status = NFS4ERR_ISDIR;
		else
			status = NFS4ERR_INVAL;
		goto out;
	}

	/* search for conflicting share reservation (deny write) */
	ss.match = FALSE;
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
		mem = realloc(ino->data, new_size);
		if (!mem) {
			status = NFS4ERR_NOSPC;
			goto out;
		}

		ino->data = mem;
		ino->size = new_size;

		memcpy(ino->data + arg->offset, arg->data.data_val, data_len);
	}

	resok->count = data_len;
	resok->committed = FILE_SYNC4;

	/* FIXME: write verifier */

out:
	res->status = status;
	return push_resop(cres, &resop, status);
}

bool_t nfs_op_read(struct nfs_cxn *cxn, READ4args *arg, COMPOUND4res *cres)
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
		syslog(LOG_INFO, "op READ (SEQ:%u ID:%x OFS:%Lu LEN:%u)",
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
	ss.match = FALSE;
	ss.ino = ino->ino;
	ss.share_dn = OPEN4_SHARE_DENY_READ;

	g_hash_table_foreach(srv.state, state_search_iter, &ss);

	if ((ss.match) && (st != ss.st)) {
		status = NFS4ERR_LOCKED;
		goto out;
	}

	if (arg->offset >= ino->size) {
		resok->eof = TRUE;
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
		resok->eof = TRUE;

out:
	res->status = status;
	return push_resop(cres, &resop, status);

out_mem:
	free(mem);
	goto out;
}
