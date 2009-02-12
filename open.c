
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
#include <syslog.h>
#include "server.h"

static const char *name_open_claim_type4[] = {
	[CLAIM_NULL] = "NULL",
	[CLAIM_PREVIOUS] = "PREVIOUS",
	[CLAIM_DELEGATE_CUR] = "DELEGATE_CUR",
	[CLAIM_DELEGATE_PREV] = "DELEGATE_PREV",
};

static nfsstat4 cur_open(struct curbuf *cur, struct nfs_open_args *args)
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

			status = cur_readattr(cur, &args->attr);
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

	syslog(LOG_INFO, "   OPEN (SEQ:%u SHAC:%x SHDN:%x CR:%s CLM:%s)",
	       args->seqid,
	       args->share_access,
	       args->share_deny,
	       args->opentype == OPEN4_CREATE ? "YES" : "NO",
	       name_open_claim_type4[args->claim]);

	if (args->opentype == OPEN4_CREATE && args->how.mode == EXCLUSIVE4) {
		uint64_t x;
		memcpy(&x, args->how.createhow4_u.createverf, 8);
		syslog(LOG_INFO, "   OPEN (MODE:EXCL VERF:%Lx)",
		       (unsigned long long) x);
	}
	else if (args->opentype == OPEN4_CREATE) {
		const char *pfx;
		if (args->how.mode == GUARDED4)
			pfx = "   OPEN (MODE:GUARD)";
		else
			pfx = "   OPEN (MODE:UNCHK)";
		print_fattr(pfx, &args->attr);
	}

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
	struct nfs_stateid sid;
	bool creating, recreating = false;
	struct nfs_open_args _args;
	struct nfs_open_args *args = &_args;
	uint64_t bitmap_set = 0;
	change_info4 cinfo = { true, 0, 0 };
	uint32_t open_flags = 0;
	struct nfs_owner *open_owner = NULL;
	struct nfs_openfile *of = NULL;
	bool new_owner = false, exclusive = false;
	nfsino_t de_inum;

	cxn->drc_mask |= drc_open;

	memset(args, 0, sizeof(struct nfs_open_args));

	status = cur_open(cur, args);
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
	status = dir_curfh(NULL, cxn, &dir_ino, 0);
	if (status != NFS4_OK)
		goto out;

	/* lookup component name; get inode if exists */
	lu_stat = dir_lookup(NULL, dir_ino, &args->u.file, 0, &de_inum);
	switch (lu_stat) {
	case NFS4ERR_NOENT:
		break;

	case NFS4_OK:
		ino = inode_getdec(NULL, de_inum, 0);
		if (!ino) {
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

	if (open_owner && ino)
		status = openfile_lookup_owner(open_owner, ino, &of);
	if (status != NFS4_OK)
		goto out;
	if (of)
		of->my_seq++;

	creating = (args->opentype == OPEN4_CREATE);
	if (creating)
		exclusive = (args->how.mode == EXCLUSIVE4);

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
		bool match_verf = false;

		if (exclusive && debugging) {
			uint64_t x;
			memcpy(&x, ino->create_verf, 8);
			syslog(LOG_DEBUG, "   OPEN (EXISTING VERF %Lx)",
			       (unsigned long long) x);
		}

		if (exclusive &&
		    !memcmp(&args->how.createhow4_u.createverf,
			    &ino->create_verf,
			    sizeof(verifier4)))
			match_verf = true;

		if (!match_verf) {
			status = NFS4ERR_EXIST;
			goto out;
		}

		creating = false;
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
		status = inode_new_type(cxn, NF4REG, NULL, NULL, &ino);
		if (status != NFS4_OK)
			goto out;

		status = inode_add(NULL, dir_ino, ino,
				   exclusive ? NULL : &args->attr,
				   &args->u.file, &bitmap_set, &cinfo);
		if (status != NFS4_OK)
			goto out;

		if (exclusive) {
			memcpy(&ino->create_verf,
			       &args->how.createhow4_u.createverf,
			       sizeof(verifier4));
			if (debugging) {
				uint64_t x, y;
				memcpy(&x, args->how.createhow4_u.createverf, 8);
				memcpy(&y, ino->create_verf, 8);
				syslog(LOG_DEBUG, "   OPEN (OLD VERF %Lx)",
					(unsigned long long) x);
				syslog(LOG_DEBUG, "   OPEN (STORED VERF %Lx)",
					(unsigned long long) y);
			}
		}
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
	if (recreating && !exclusive) {
		_args.attr.supported_attrs &= (1ULL << FATTR4_SIZE);

		status = inode_apply_attrs(NULL, ino, &args->attr, &bitmap_set,
					   NULL, false);
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

	if (!of) {
		of = openfile_new(nst_open, open_owner);
		if (!of) {
			status = NFS4ERR_RESOURCE;
			goto err_out;
		}

		of->ino = ino->inum;
		of->u.share.access = args->share_access;
		of->u.share.deny = args->share_deny;

		list_add(&of->inode_node, &ino->openfile_list);
		list_add(&of->owner_node, &open_owner->openfiles);
		g_hash_table_insert(srv.openfiles, GUINT_TO_POINTER(of->id),of);
	}

	if (new_owner)
		open_flags |= OPEN4_RESULT_CONFIRM;
	else
		of->flags |= nsf_confirmed;

	sid.seqid = of->my_seq;
	sid.id = of->id;
	memcpy(&sid.server_verf, &srv.instance_verf, 4);
	memcpy(&sid.server_magic, SRV_MAGIC, 4);

	status = NFS4_OK;

	fh_set(&cxn->current_fh, ino->inum);

	if (debugging)
		syslog(LOG_INFO, "   OPEN -> (SEQ:%u ID:%x)",
		       sid.seqid, of->id);

out:
	fattr_free(&args->attr);

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
		owner_free(open_owner);
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

	ino = inode_fhdec(NULL, cxn->current_fh, 0);
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

	if (seqid != of->owner->cli_next_seq) {
		status = NFS4ERR_BAD_SEQID;
		goto out;
	}

	if (of->flags & nsf_confirmed) {
		status = NFS4ERR_BAD_STATEID;
		goto out;
	}

	of->flags |= nsf_confirmed;

	of->owner->cli_next_seq++;
	of->my_seq++;

	sid.seqid = of->my_seq;
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

	ino = inode_fhdec(NULL, cxn->current_fh, 0);
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

	if (seqid != of->owner->cli_next_seq) {
		status = NFS4ERR_BAD_SEQID;
		goto out;
	}

	of->my_seq++;
	of->owner->cli_next_seq++;

	if (!share_access) {
		status = NFS4ERR_INVAL;
		goto out;
	}
	if (share_access &&
	    ((share_access & of->u.share.access) != share_access)) {
		status = NFS4ERR_INVAL;
		goto out;
	}
	if (share_deny &&
	    ((share_deny & of->u.share.deny) != share_deny)) {
		status = NFS4ERR_INVAL;
		goto out;
	}

	of->u.share.access = share_access;
	of->u.share.deny = share_deny;

	sid.seqid = of->my_seq;
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

	ino = inode_fhdec(NULL, cxn->current_fh, 0);
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

	if (seqid != of->owner->cli_next_seq) {
		status = NFS4ERR_BAD_SEQID;
		goto out;
	}

	of->owner->cli_next_seq++;

	openfile_trash(of, false);

	/* really only for completeness */
	of->my_seq++;
	sid.seqid = of->my_seq;

out:
	WR32(status);
	if (status == NFS4_OK)
		WRSID(&sid);
	return status;
}

