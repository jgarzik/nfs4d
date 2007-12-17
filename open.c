
#define _GNU_SOURCE
#include <string.h>
#include <syslog.h>
#include "server.h"

static const char *name_open_claim_type4[] = {
	[CLAIM_NULL] = "NULL",
	[CLAIM_PREVIOUS] = "PREVIOUS",
	[CLAIM_DELEGATE_CUR] = "DELEGATE_CUR",
	[CLAIM_DELEGATE_PREV] = "DELEGATE_PREV",
};

static nfsstat4 cur_open(struct curbuf *cur, OPEN4args *args,
			 struct nfs_fattr_set *attr)
{
	if (cur->len < (6 * 4))
		return NFS4ERR_BADXDR;

	args->seqid = CR32();
	args->share_access = CR32();
	args->share_deny = CR32();
	args->owner.clientid = CR64();
	CURBUF((struct nfs_buf *) &args->owner.owner);

	args->openhow.opentype = CR32();
	if (args->openhow.opentype == OPEN4_CREATE) {
		createhow4 *how = &args->openhow.openflag4_u.how;
		how->mode = CR32();
		if (how->mode == EXCLUSIVE4) {
			if (cur->len < 8)
				return NFS4ERR_BADXDR;

			memcpy(&how->createhow4_u.createverf,
			       CURMEM(sizeof(verifier4)),
			       sizeof(verifier4));
		} else if ((how->mode == UNCHECKED4) ||
			   (how->mode == GUARDED4)) {
			nfsstat4 status;

			status = cur_readattr(cur, attr);
			if (status != NFS4_OK)
				return status;
		} else
			return NFS4ERR_BADXDR;
	} else if (args->openhow.opentype != OPEN4_NOCREATE)
		return NFS4ERR_BADXDR;

	args->claim.claim = CR32();
	switch (args->claim.claim) {
	case CLAIM_NULL:
		CURBUF((struct nfs_buf *)
			&args->claim.open_claim4_u.file);
		break;

	case CLAIM_PREVIOUS:
		args->claim.open_claim4_u.delegate_type = CR32();
		break;

	case CLAIM_DELEGATE_CUR:
		if (cur->len < 20)
			return NFS4ERR_BADXDR;
		CURSID((struct nfs_stateid *)
			&args->claim.open_claim4_u.delegate_cur_info.delegate_stateid);
		CURBUF((struct nfs_buf *)
			&args->claim.open_claim4_u.delegate_cur_info.file);
		break;

	case CLAIM_DELEGATE_PREV:
		CURBUF((struct nfs_buf *)
			&args->claim.open_claim4_u.file_delegate_prev);
		break;
	default:
		return NFS4ERR_BADXDR;
	}

	return NFS4_OK;
}

static void print_open_args(OPEN4args *args)
{
	if (!debugging)
		return;

	syslog(LOG_INFO, "op OPEN ('%.*s')",
	       args->claim.open_claim4_u.file.utf8string_len,
	       args->claim.open_claim4_u.file.utf8string_val);

	syslog(LOG_INFO, "   OPEN (SEQ:%u SHAC:%x SHDN:%x HOW:%s CLM:%s)",
	       args->seqid,
	       args->share_access,
	       args->share_deny,
	       args->openhow.opentype == OPEN4_CREATE ? "CR" : "NOC",
	       name_open_claim_type4[args->claim.claim]);

	syslog(LOG_INFO, "   OPEN (CID:%Lx OWNER:%.*s)",
	       (unsigned long long) args->owner.clientid,
	       args->owner.owner.owner_len,
	       args->owner.owner.owner_val);
}

nfsstat4 nfs_op_open(struct nfs_cxn *cxn, struct curbuf *cur,
		     struct list_head *writes, struct rpc_write **wr)
{
	nfsstat4 status, lu_stat;
	struct nfs_inode *dir_ino, *ino = NULL;
	struct nfs_dirent *de;
	struct nfs_state *st;
	struct nfs_stateid sid;
	bool creating, recreating = false;
	OPEN4args _args;
	OPEN4args *args = &_args;
	struct nfs_fattr_set attr;
	uint64_t bitmap_set = 0;
	change_info4 cinfo = { true, 0, 0 };

	memset(&attr, 0, sizeof(attr));

	status = cur_open(cur, args, &attr);
	if (status != NFS4_OK)
		goto out;

	print_open_args(args);

	/* for the moment, we only support CLAIM_NULL */
	if (args->claim.claim != CLAIM_NULL) {
		status = NFS4ERR_NOTSUPP;
		goto out;
	}

	/* get directory handle */
	status = dir_curfh(cxn, &dir_ino);
	if (status != NFS4_OK)
		goto out;

	/* lookup component name; get inode if exists */
	lu_stat = dir_lookup(dir_ino,
			     (struct nfs_buf *) &args->claim.open_claim4_u.file,
			     &de);
	switch (lu_stat) {
	case NFS4ERR_NOENT:
		break;

	case NFS4_OK:
		ino = inode_get(de->ino);
		if (!ino) {	/* should never happen */
			status = NFS4ERR_SERVERFAULT;
			goto out;
		}
		break;

	default:
		status = lu_stat;
		goto out;
	}

	creating = (args->openhow.opentype == OPEN4_CREATE);

	if (creating && ino &&
	    (args->openhow.openflag4_u.how.mode == UNCHECKED4)) {
		creating = false;
		recreating = true;
	}

	/*
	 * does the dirent's existence match our expectations?
	 */
	if (!creating && (lu_stat == NFS4ERR_NOENT)) {
		status = lu_stat;
		goto out;
	}
	if (creating && (lu_stat == NFS4_OK)) {
		status = NFS4ERR_EXIST;
		goto out;
	}

	/*
	 * validate share reservations
	 */
	if ((args->share_access & OPEN4_SHARE_ACCESS_BOTH) == 0) {
		status = NFS4ERR_INVAL;
		goto out;
	}

	if (ino) {
		status = access_ok(NULL, ino->ino,
			   args->share_access & OPEN4_SHARE_ACCESS_WRITE,
			   0, 0, NULL, NULL);
		if (status != NFS4_OK)
			goto out;
	}

	/*
	 * look up shorthand client id (clientid4)
	 */
	status = clientid_test(args->owner.clientid);
	if (status != NFS4_OK)
		goto out;

	/*
	 * create file, if necessary
	 */
	if (creating) {
		ino = inode_new_file(cxn);
		if (!ino) {
			status = NFS4ERR_RESOURCE;
			goto out;
		}

		status = inode_add(dir_ino, ino, &attr,
			   (struct nfs_buf *) &args->claim.open_claim4_u.file,
			   &bitmap_set, &cinfo);
		if (status != NFS4_OK)
			goto out;
	}

	/* FIXME: undo file creation, if this test fails? */
	if (ino->type != NF4REG) {
		if (ino->type == NF4DIR)
			status = NFS4ERR_ISDIR;
		else if (ino->type == NF4LNK)
			status = NFS4ERR_SYMLINK;
		else
			status = NFS4ERR_INVAL;
		goto out;
	}

	/*
	 * if re-creating, only size attribute applies
	 */
	if (recreating) {
		attr.supported_attrs &= (1ULL << FATTR4_SIZE);

		status = inode_apply_attrs(ino, &attr, &bitmap_set, NULL,false);
		if (status != NFS4_OK)
			goto out;
	}

	st = state_new(nst_open, (struct nfs_buf *) &args->owner.owner);
	if (!st) {
		status = NFS4ERR_RESOURCE;
		goto out;
	}

	st->cli = args->owner.clientid;
	st->ino = ino->ino;
	st->seq = args->seqid + 1;
	st->u.share.access = args->share_access;
	st->u.share.deny = args->share_deny;

	g_hash_table_insert(srv.state, GUINT_TO_POINTER(st->id), st);

	sid.seqid = args->seqid + 1;
	sid.id = st->id;
	memcpy(&sid.server_verf, &srv.instance_verf, sizeof(srv.instance_verf));

	status = NFS4_OK;
	cxn->current_fh = ino->ino;

	if (debugging)
		syslog(LOG_INFO, "   OPEN -> (SEQ:%u ID:%x)",
		       sid.seqid, st->id);

out:
	fattr_free(&attr);

	WR32(status);
	if (status == NFS4_OK) {
		WRSID(&sid);
		WR32(cinfo.atomic);
		WR64(cinfo.before);
		WR64(cinfo.after);
		WR32(OPEN4_RESULT_LOCKTYPE_POSIX);
		WRMAP(bitmap_set);
		WR32(OPEN_DELEGATE_NONE);
		/* FIXME: handle open delegations */
	}
	return status;
}

nfsstat4 nfs_op_open_confirm(struct nfs_cxn *cxn, struct curbuf *cur,
			     struct list_head *writes, struct rpc_write **wr)
{
	nfsstat4 status = NFS4_OK;
	struct nfs_stateid sid;
	struct nfs_state *st = NULL;
	struct nfs_inode *ino;
	uint32_t seqid;

	if (cur->len < 20) {
		status = NFS4ERR_BADXDR;
		goto out;
	}

	CURSID(&sid);
	seqid = CR32();

	if (debugging)
		syslog(LOG_INFO, "op OPEN_CONFIRM (SEQ:%u IDSEQ:%u ID:%x)",
		       seqid, sid.seqid, sid.id);

	ino = inode_get(cxn->current_fh);
	if (!ino) {
		status = NFS4ERR_NOFILEHANDLE;
		goto out;
	}

	if (ino->type != NF4REG) {
		if (ino->type == NF4DIR)
			status = NFS4ERR_ISDIR;
		else
			status = NFS4ERR_INVAL;
		goto out;
	}

	status = stateid_lookup(sid.id, ino->ino, nst_open, &st);
	if (status != NFS4_OK)
		goto out;

	if (seqid != st->seq) {
		status = NFS4ERR_BAD_SEQID;
		goto out;
	}

	sid.seqid = seqid;
	sid.id = st->id;
	memcpy(&sid.server_verf, &srv.instance_verf, sizeof(srv.instance_verf));

out:
	WR32(status);
	if (status == NFS4_OK)
		WRSID(&sid);
	return status;
}

nfsstat4 nfs_op_open_downgrade(struct nfs_cxn *cxn, struct curbuf *cur,
			     struct list_head *writes, struct rpc_write **wr)
{
	nfsstat4 status = NFS4_OK;
	struct nfs_stateid sid;
	struct nfs_state *st = NULL;
	struct nfs_inode *ino;
	uint32_t seqid, share_access, share_deny;

	if (cur->len < 28) {
		status = NFS4ERR_BADXDR;
		goto out;
	}

	CURSID(&sid);
	seqid = CR32();
	share_access = CR32();
	share_deny = CR32();

	if (debugging)
		syslog(LOG_INFO, "op OPEN_DOWNGRADE (SEQ:%u IDSEQ:%u ID:%x "
		       "SHAC:%x SHDN:%x)",
		       seqid, sid.seqid, sid.id,
		       share_access, share_deny);

	ino = inode_get(cxn->current_fh);
	if (!ino) {
		status = NFS4ERR_NOFILEHANDLE;
		goto out;
	}

	if (ino->type != NF4REG) {
		status = NFS4ERR_INVAL;
		goto out;
	}

	status = stateid_lookup(sid.id, ino->ino, nst_open, &st);
	if (status != NFS4_OK)
		goto out;

	if (seqid != st->seq) {
		status = NFS4ERR_BAD_SEQID;
		goto out;
	}

	if ((!(share_access & st->u.share.access)) ||
	    (!(share_deny & st->u.share.deny))) {
		status = NFS4ERR_INVAL;
		goto out;
	}

	st->u.share.access = share_access;
	st->u.share.deny = share_deny;

	st->seq++;

	sid.seqid = st->seq;
	sid.id = st->id;
	memcpy(&sid.server_verf, &srv.instance_verf, sizeof(srv.instance_verf));

	if (debugging)
		syslog(LOG_INFO, "   OPEN_DOWNGRADE -> (SEQ:%u ID:%x)",
		       sid.seqid, st->id);

out:
	WR32(status);
	if (status == NFS4_OK)
		WRSID(&sid);
	return status;
}

struct close_lock_info {
	struct nfs_state	*open_st;
	GList			*list;
};

static void close_lock_iter(gpointer key, gpointer val, gpointer user_data)
{
	struct nfs_state *st = val;
	struct close_lock_info *cl = user_data;

	if (st->type == nst_lock &&
	    st->u.lock.open == cl->open_st)
		cl->list = g_list_prepend(cl->list, st);
}

nfsstat4 nfs_op_close(struct nfs_cxn *cxn, struct curbuf *cur,
		      struct list_head *writes, struct rpc_write **wr)
{
	nfsstat4 status = NFS4_OK;
	struct nfs_stateid sid;
	struct nfs_state *st;
	struct nfs_inode *ino;
	uint32_t seqid;
	GList *tmp;
	struct close_lock_info cl;

	if (cur->len < 20) {
		status = NFS4ERR_BADXDR;
		goto out;
	}

	seqid = CR32();
	CURSID(&sid);

	if (debugging)
		syslog(LOG_INFO, "op CLOSE (SEQ:%u IDSEQ:%u ID:%x)",
		       seqid, sid.seqid, sid.id);

	ino = inode_get(cxn->current_fh);
	if (!ino) {
		status = NFS4ERR_NOFILEHANDLE;
		goto out;
	}

	if (ino->type != NF4REG) {
		status = NFS4ERR_INVAL;
		goto out;
	}

	status = stateid_lookup(sid.id, ino->ino, nst_open, &st);
	if (status != NFS4_OK)
		goto out;

	if (seqid != st->seq) {
		status = NFS4ERR_BAD_SEQID;
		goto out;
	}

	cl.open_st = st;
	cl.list = NULL;

	g_hash_table_foreach(srv.state, close_lock_iter, &cl);

	tmp = cl.list;
	while (tmp) {
		state_trash(tmp->data);
		tmp = tmp->next;
	}
	g_list_free(cl.list);

	state_trash(st);

out:
	WR32(status);
	if (status == NFS4_OK)
		WRSID(&sid);
	return status;
}

