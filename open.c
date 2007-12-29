
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

static nfsstat4 cur_open(struct curbuf *cur, struct nfs_open_args *args,
			 struct nfs_fattr_set *attr)
{
	if (cur->len < (6 * 4))
		return NFS4ERR_BADXDR;

	args->seqid = CR32();
	args->share_access = CR32();
	args->share_deny = CR32();
	args->clientid = CR64();
	CURBUF(&args->owner);

	args->opentype = CR32();
	if (args->opentype == OPEN4_CREATE) {
		createhow4 *how = &args->how;
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
	} else if (args->opentype != OPEN4_NOCREATE)
		return NFS4ERR_BADXDR;

	args->claim = CR32();
	switch (args->claim) {
	case CLAIM_NULL:
		CURBUF(&args->u.file);
		break;

	case CLAIM_PREVIOUS:
		args->u.delegate_type = CR32();
		break;

	case CLAIM_DELEGATE_CUR:
		if (cur->len < 20)
			return NFS4ERR_BADXDR;
		CURSID(&args->u.delegate_cur_info.delegate_stateid);
		CURBUF(&args->u.delegate_cur_info.file);
		break;

	case CLAIM_DELEGATE_PREV:
		CURBUF(&args->u.file_delegate_prev);
		break;
	default:
		return NFS4ERR_BADXDR;
	}

	return NFS4_OK;
}

static void print_open_args(struct nfs_open_args *args)
{
	if (!debugging)
		return;

	syslog(LOG_INFO, "op OPEN ('%.*s')",
	       args->u.file.len,
	       args->u.file.val);

	syslog(LOG_INFO, "   OPEN (SEQ:%u SHAC:%x SHDN:%x HOW:%s CLM:%s)",
	       args->seqid,
	       args->share_access,
	       args->share_deny,
	       args->opentype == OPEN4_CREATE ? "CR" : "NOC",
	       name_open_claim_type4[args->claim]);

	syslog(LOG_INFO, "   OPEN (CID:%Lx OWNER:%.*s)",
	       (unsigned long long) args->clientid,
	       args->owner.len,
	       args->owner.val);
}

nfsstat4 nfs_op_open(struct nfs_cxn *cxn, struct curbuf *cur,
		     struct list_head *writes, struct rpc_write **wr)
{
	nfsstat4 status, lu_stat;
	struct nfs_inode *dir_ino, *ino = NULL;
	struct nfs_dirent *de;
	struct nfs_stateid sid;
	bool creating, recreating = false;
	struct nfs_open_args _args;
	struct nfs_open_args *args = &_args;
	struct nfs_fattr_set attr;
	uint64_t bitmap_set = 0;
	change_info4 cinfo = { true, 0, 0 };
	uint32_t open_flags = 0;
	struct nfs_owner *open_owner = NULL;
	struct nfs_openfile *of = NULL;
	bool new_owner = false;

	cxn->drc_mask |= drc_open;

	memset(&attr, 0, sizeof(attr));

	status = cur_open(cur, args, &attr);
	if (status != NFS4_OK)
		goto out;

	print_open_args(args);

	status = owner_lookup_name(args->clientid, &args->owner, &open_owner);
	if (status != NFS4_OK)
		goto out;

	if (open_owner) {
		if (args->seqid != open_owner->cli_next_seq) {
			status = NFS4ERR_BAD_SEQID;
			goto out;
		}

		open_owner->my_seq++;
		open_owner->cli_next_seq++;
	}

	/* for the moment, we only support CLAIM_NULL */
	if (args->claim != CLAIM_NULL) {
		if (args->claim == CLAIM_PREVIOUS)
			status = NFS4ERR_RECLAIM_BAD;
		else
			status = NFS4ERR_NOTSUPP;
		goto out;
	}

	/* get directory handle */
	status = dir_curfh(cxn, &dir_ino);
	if (status != NFS4_OK)
		goto out;

	/* lookup component name; get inode if exists */
	lu_stat = dir_lookup(dir_ino, &args->u.file, &de);
	switch (lu_stat) {
	case NFS4ERR_NOENT:
		break;

	case NFS4_OK:
		ino = inode_get(de->ino_n);
		if (!ino || (ino->generation != de->generation)) {
			status = NFS4ERR_NOENT;
			goto out;
		}
		if (ino->type != NF4REG) {
			if (ino->type == NF4DIR)
				status = NFS4ERR_ISDIR;
			else if (ino->type == NF4LNK)
				status = NFS4ERR_SYMLINK;
			else
				status = NFS4ERR_INVAL;
			goto out;
		}
		break;

	default:
		status = lu_stat;
		goto out;
	}

	creating = (args->opentype == OPEN4_CREATE);

	if (creating && ino &&
	    (args->how.mode == UNCHECKED4)) {
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
		struct nfs_access ac = { NULL, };

		ac.ino = ino;
		ac.op = OP_OPEN;
		ac.clientid = args->clientid;
		ac.owner = &args->owner;
		ac.share_access = args->share_access;
		ac.share_deny = args->share_deny;
		status = access_ok(&ac);
		if (status != NFS4_OK)
			goto out;
	}

	/*
	 * create file, if necessary
	 */
	if (creating) {
		ino = inode_new_file(cxn);
		if (!ino) {
			status = NFS4ERR_RESOURCE;
			goto out;
		}

		status = inode_add(dir_ino, ino, &attr, &args->u.file,
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

	if (!ino->mode) {
		status = NFS4ERR_ACCESS;
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

	if (!open_owner) {
		open_owner = owner_new(nst_open, &args->owner);
		if (!open_owner) {
			status = NFS4ERR_RESOURCE;
			goto out;
		}

		open_owner->cli = args->clientid;
		open_owner->cli_next_seq = args->seqid + 1;

		cli_owner_add(open_owner);

		new_owner = true;
	}

	of = openfile_new(nst_open, open_owner);
	if (!of) {
		status = NFS4ERR_RESOURCE;
		goto err_out;
	}

	of->ino = ino;
	of->u.share.access = args->share_access;
	of->u.share.deny = args->share_deny;

	list_add(&of->inode_node, &ino->openfile_list);
	list_add(&of->owner_node, &open_owner->openfiles);
	of->flags |= nsf_owned;
	g_hash_table_insert(srv.openfiles, GUINT_TO_POINTER(of->id), of);

	if (new_owner)
		open_flags |= OPEN4_RESULT_CONFIRM;

	sid.seqid = open_owner->my_seq;
	sid.id = of->id;
	memcpy(&sid.server_verf, &srv.instance_verf, 4);
	memcpy(&sid.server_magic, SRV_MAGIC, 4);

	status = NFS4_OK;
	cxn->current_fh = ino->ino;

	if (debugging)
		syslog(LOG_INFO, "   OPEN -> (SEQ:%u ID:%x)",
		       sid.seqid, of->id);

out:
	fattr_free(&attr);

	WR32(status);
	if (status == NFS4_OK) {
		WRSID(&sid);
		WR32(cinfo.atomic);
		WR64(cinfo.before);
		WR64(cinfo.after);
		WR32(open_flags);
		WRMAP(bitmap_set);
		WR32(OPEN_DELEGATE_NONE);
		/* FIXME: handle open delegations */
	}
	return status;

err_out:
	if (new_owner) {
		free(open_owner);
		open_owner = NULL;
	}
	goto out;
}

nfsstat4 nfs_op_open_confirm(struct nfs_cxn *cxn, struct curbuf *cur,
			     struct list_head *writes, struct rpc_write **wr)
{
	nfsstat4 status = NFS4_OK;
	struct nfs_stateid sid;
	struct nfs_inode *ino;
	uint32_t seqid;
	struct nfs_owner *open_owner = NULL;
	struct nfs_openfile *of = NULL;

	cxn->drc_mask |= drc_open;

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

	status = openfile_lookup(&sid, ino, nst_open, &of);
	if (status != NFS4_OK)
		goto out;
	open_owner = of->owner;

	if (seqid != open_owner->cli_next_seq) {
		status = NFS4ERR_BAD_SEQID;
		goto out;
	}

	/* FIXME: actually confirm.... */

	open_owner->cli_next_seq++;
	open_owner->my_seq++;

	sid.seqid = open_owner->my_seq;
	sid.id = of->id;
	memcpy(&sid.server_verf, &srv.instance_verf, 4);
	memcpy(&sid.server_magic, SRV_MAGIC, 4);

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
	struct nfs_inode *ino;
	uint32_t seqid, share_access, share_deny;
	struct nfs_owner *open_owner = NULL;
	struct nfs_openfile *of = NULL;

	cxn->drc_mask |= drc_open;

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

	status = openfile_lookup(&sid, ino, nst_open, &of);
	if (status != NFS4_OK)
		goto out;
	open_owner = of->owner;

	if (seqid != open_owner->cli_next_seq) {
		status = NFS4ERR_BAD_SEQID;
		goto out;
	}

	open_owner->my_seq++;
	open_owner->cli_next_seq++;

	if ((!(share_access & of->u.share.access)) ||
	    (!(share_deny & of->u.share.deny))) {
		status = NFS4ERR_INVAL;
		goto out;
	}

	of->u.share.access = share_access;
	of->u.share.deny = share_deny;

	sid.seqid = open_owner->my_seq;
	sid.id = of->id;
	memcpy(&sid.server_verf, &srv.instance_verf, 4);
	memcpy(&sid.server_magic, SRV_MAGIC, 4);

	if (debugging)
		syslog(LOG_INFO, "   OPEN_DOWNGRADE -> (SEQ:%u ID:%x)",
		       sid.seqid, of->id);

out:
	WR32(status);
	if (status == NFS4_OK)
		WRSID(&sid);
	return status;
}

nfsstat4 nfs_op_close(struct nfs_cxn *cxn, struct curbuf *cur,
		      struct list_head *writes, struct rpc_write **wr)
{
	nfsstat4 status = NFS4_OK;
	struct nfs_stateid sid;
	struct nfs_openfile *of = NULL;
	struct nfs_inode *ino;
	uint32_t seqid;
	struct nfs_owner *open_owner = NULL;

	cxn->drc_mask |= drc_close;

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

	status = openfile_lookup(&sid, ino, nst_open, &of);
	if (status != NFS4_OK)
		goto out;
	if (of)
		open_owner = of->owner;

	if (seqid != open_owner->cli_next_seq) {
		status = NFS4ERR_BAD_SEQID;
		goto out;
	}

	openfile_trash(of, false);

	/* really only for completeness... */
	open_owner->cli_next_seq++;
	open_owner->my_seq++;
	sid.seqid = open_owner->my_seq;

out:
	WR32(status);
	if (status == NFS4_OK)
		WRSID(&sid);
	return status;
}

