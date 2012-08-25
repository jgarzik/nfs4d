
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

static void print_open_args(const OPEN4args *args)
{
	if (!debugging)
		return;

	applog(LOG_INFO, "op OPEN");

	applog(LOG_INFO, "   OPEN (SEQ:%u SHAC:%x SHDN:%x CR:%s CLM:%s)",
	       args->seqid,
	       args->share_access,
	       args->share_deny,
	       args->openhow.opentype == OPEN4_CREATE ? "YES" : "NO",
	       name_open_claim_type4[args->claim.claim]);

	if (args->openhow.opentype == OPEN4_CREATE && args->openhow.openflag4_u.how.mode == EXCLUSIVE4) {
		uint64_t x;
		memcpy(&x, args->openhow.openflag4_u.how.createhow4_u.createverf, 8);
		applog(LOG_INFO, "   OPEN (MODE:EXCL VERF:%Lx)",
		       (unsigned long long) x);
	}
	else if (args->openhow.opentype == OPEN4_CREATE) {
		const char *pfx;
		if (args->openhow.openflag4_u.how.mode == GUARDED4)
			pfx = "   OPEN (MODE:GUARD)";
		else
			pfx = "   OPEN (MODE:UNCHK)";
		(void)pfx;
		//print_fattr(pfx, &args->attr);
	}

	applog(LOG_INFO, "   OPEN (CID:%016llx OWNER:%.*s)",
	       (unsigned long long) args->owner.clientid,
	       args->owner.owner.owner_len,
	       args->owner.owner.owner_val);
}

nfsstat4 nfs_op_open(struct nfs_cxn *cxn, const OPEN4args *args,
		     struct list_head *writes, struct rpc_write **wr)
{
	nfsstat4 status, lu_stat;
	struct nfs_inode *dir_ino = NULL, *ino = NULL;
	struct nfs_stateid sid;
	bool creating, recreating = false;
	uint64_t bitmap_set = 0;
	change_info4 cinfo = { true, 0, 0 };
	uint32_t open_flags = 0;
	struct nfs_owner *open_owner = NULL;
	struct nfs_openfile *of = NULL;
	struct nfs_buf owner_name, u_file;
	struct nfs_fattr_set args_attr = {};
	bool new_owner = false, exclusive = false;
	nfsino_t de_inum;
	DB_TXN *txn;
	DB_ENV *dbenv = srv.fsdb.env;
	int rc;

	cxn->drc_mask |= drc_open;

	print_open_args(args);

	owner_name.len = args->owner.owner.owner_len;
	owner_name.val = args->owner.owner.owner_val;
	u_file.len = args->claim.open_claim4_u.file.utf8string_len;
	u_file.val = args->claim.open_claim4_u.file.utf8string_val;
	clientid4 clientid = cxn->sess.client;

	/* open transaction */
	rc = dbenv->txn_begin(dbenv, NULL, &txn, 0);
	if (rc) {
		status = NFS4ERR_IO;
		dbenv->err(dbenv, rc, "DB_ENV->txn_begin");
		goto out;
	}

	status = owner_lookup_name(clientid, &owner_name, &open_owner);
	if (status != NFS4_OK)
		goto err_out;

	if (open_owner)
		open_owner->cli_next_seq++;

	/* for the moment, we only support CLAIM_NULL */
	if (args->claim.claim != CLAIM_NULL) {
		if (args->claim.claim == CLAIM_PREVIOUS)
			status = NFS4ERR_RECLAIM_BAD;
		else
			status = NFS4ERR_NOTSUPP;
		goto err_out;
	}

	/* get directory handle */
	status = dir_curfh(txn, cxn, &dir_ino, 0);
	if (status != NFS4_OK)
		goto err_out;

	/* lookup component name; get inode if exists */
	lu_stat = dir_lookup(txn, dir_ino, &u_file, 0, &de_inum);
	switch (lu_stat) {
	case NFS4ERR_NOENT:
		break;

	case NFS4_OK:
		ino = inode_getdec(txn, de_inum, 0);
		if (!ino) {
			status = NFS4ERR_NOENT;
			goto err_out;
		}
		if (ino->type != NF4REG) {
			if (ino->type == NF4DIR)
				status = NFS4ERR_ISDIR;
			else if (ino->type == NF4LNK)
				status = NFS4ERR_SYMLINK;
			else
				status = NFS4ERR_INVAL;
			goto err_out;
		}
		break;

	default:
		status = lu_stat;
		goto err_out;
	}

	if (open_owner && ino)
		status = openfile_lookup_owner(open_owner, ino, &of);
	if (status != NFS4_OK)
		goto err_out;
	if (of)
		of->my_seq++;

	creating = (args->openhow.opentype == OPEN4_CREATE);
	if (creating) {
		switch (args->openhow.openflag4_u.how.mode) {
		case UNCHECKED4:
		case GUARDED4:
			exclusive = false;
			copy_attr(&args_attr, &args->openhow.openflag4_u.how.createhow4_u.createattrs);
			break;
		case EXCLUSIVE4:
			exclusive = true;
			break;
		case EXCLUSIVE4_1:
			copy_attr(&args_attr, &args->openhow.openflag4_u.how.createhow4_u.ch_createboth.cva_attrs);
			exclusive = true;
			break;
		}
	}

	if (creating && ino &&
	    (args->openhow.openflag4_u.how.mode == UNCHECKED4)) {
		creating = false;
		recreating = true;

		if (debugging > 1)
			applog(LOG_DEBUG, "   OPEN unchecked: recreating");
	}

	/*
	 * does the dirent's existence match our expectations?
	 */
	if (!creating && (lu_stat == NFS4ERR_NOENT)) {
		status = lu_stat;
		goto err_out;
	}
	if (creating && (lu_stat == NFS4_OK)) {
		bool match_verf = false;

		if (exclusive && debugging) {
			uint64_t x;
			memcpy(&x, ino->create_verf, 8);
			applog(LOG_DEBUG, "   OPEN (EXISTING VERF %Lx)",
			       (unsigned long long) x);
		}

		if (exclusive &&
		    !memcmp(&args->openhow.openflag4_u.how.createhow4_u.createverf,
			    &ino->create_verf,
			    sizeof(verifier4)))
			match_verf = true;

		if (!match_verf) {
			status = NFS4ERR_EXIST;
			goto err_out;
		}

		creating = false;
	}

	/*
	 * validate share reservations
	 */
	if ((args->share_access & OPEN4_SHARE_ACCESS_BOTH) == 0) {
		status = NFS4ERR_INVAL;
		goto err_out;
	}

	if (ino) {
		struct nfs_access ac = { NULL, };

		ac.ino = ino;
		ac.op = OP_OPEN;
		ac.clientid = clientid;
		ac.owner = &owner_name;
		ac.share_access = args->share_access;
		ac.share_deny = args->share_deny;
		status = access_ok(&ac);
		if (status != NFS4_OK)
			goto err_out;
	}

	/*
	 * create file, if necessary
	 */
	if (creating) {
		status = inode_new_type(txn, cxn, NF4REG, dir_ino,
					NULL, NULL, &ino);
		if (status != NFS4_OK)
			goto err_out;

		status = inode_add(txn, dir_ino, ino,
				   exclusive ? NULL : &args_attr,
				   &u_file, &bitmap_set, &cinfo);
		if (status != NFS4_OK)
			goto err_out;

		if (exclusive) {
			memcpy(&ino->create_verf,
			       &args->openhow.openflag4_u.how.createhow4_u.createverf,
			       sizeof(verifier4));
			if (debugging) {
				uint64_t x, y;
				memcpy(&x, args->openhow.openflag4_u.how.createhow4_u.createverf, 8);
				memcpy(&y, ino->create_verf, 8);
				applog(LOG_DEBUG, "   OPEN (OLD VERF %Lx)",
					(unsigned long long) x);
				applog(LOG_DEBUG, "   OPEN (STORED VERF %Lx)",
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
		goto err_out;
	}

	if (!ino->mode) {
		status = NFS4ERR_ACCESS;
		goto err_out;
	}

	/*
	 * if re-creating, only size attribute applies
	 */
	if (recreating && !exclusive) {
		args_attr.bitmap &= (1ULL << FATTR4_SIZE);

		status = NFS4_OK;
		if (args_attr.size == 0)
			status = inode_apply_attrs(txn, ino, &args_attr,
						   &bitmap_set, NULL, false);
		if (status != NFS4_OK)
			goto err_out;
	}

	if (!open_owner) {
		open_owner = owner_new(nst_open, &owner_name);
		if (!open_owner) {
			status = NFS4ERR_RESOURCE;
			goto err_out;
		}

		open_owner->cli = clientid;

		cli_owner_add(open_owner);

		new_owner = true;
	}

	if (!of) {
		of = openfile_new(nst_open, open_owner);
		if (!of) {
			status = NFS4ERR_RESOURCE;
			goto err_out;
		}

		of->inum = ino->inum;
		of->share_access = args->share_access;
		of->share_deny = args->share_deny;

		list_add(&of->inode_node, &ino_openfile_list);
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

	if (inode_touch(txn, ino)) {
		status = NFS4ERR_IO;
		goto err_out;
	}

	/* close transaction */
	rc = txn->commit(txn, 0);
	if (rc) {
		dbenv->err(dbenv, rc, "DB_ENV->txn_commit");
		status = NFS4ERR_IO;
		goto err_out_owner;
	}

	status = NFS4_OK;

	fh_set(&cxn->current_fh, ino->inum);

	if (debugging)
		applog(LOG_INFO, "   OPEN -> (SID.SEQ:%u SID.ID:%x)",
		       sid.seqid, sid.id);

out:
	fattr_free(&args_attr);

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

	inode_free(dir_ino);
	inode_free(ino);
	return status;

err_out:
	if (txn->abort(txn))
		dbenv->err(dbenv, rc, "DB_ENV->txn_abort");
err_out_owner:
	if (new_owner)
		owner_free(open_owner);
	goto out;
}

nfsstat4 nfs_op_open_downgrade(struct nfs_cxn *cxn, const OPEN_DOWNGRADE4args *args,
			     struct list_head *writes, struct rpc_write **wr)
{
	nfsstat4 status = NFS4_OK;
	struct nfs_stateid sid;
	struct nfs_inode *ino = NULL;
	uint32_t share_access, share_deny;
	struct nfs_openfile *of = NULL;

	cxn->drc_mask |= drc_open;

	copy_sid(&sid, &args->open_stateid);
	share_access = args->share_access;
	share_deny = args->share_deny;

	if (debugging)
		applog(LOG_INFO, "op OPEN_DOWNGRADE (SEQ:%u IDSEQ:%u ID:%x "
		       "SHAC:%x SHDN:%x)",
		       args->seqid, sid.seqid, sid.id,
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

	of->my_seq++;
	of->owner->cli_next_seq++;

	if (!share_access) {
		status = NFS4ERR_INVAL;
		goto out;
	}
	if (share_access &&
	    ((share_access & of->share_access) != share_access)) {
		status = NFS4ERR_INVAL;
		goto out;
	}
	if (share_deny &&
	    ((share_deny & of->share_deny) != share_deny)) {
		status = NFS4ERR_INVAL;
		goto out;
	}

	of->share_access = share_access;
	of->share_deny = share_deny;

	sid.seqid = of->my_seq;
	sid.id = of->id;
	memcpy(&sid.server_verf, &srv.instance_verf, 4);
	memcpy(&sid.server_magic, SRV_MAGIC, 4);

	if (debugging)
		applog(LOG_INFO, "   OPEN_DOWNGRADE -> (SID.SEQ:%u ID:%x)",
		       sid.seqid, of->id);

out:
	WR32(status);
	if (status == NFS4_OK)
		WRSID(&sid);
	inode_free(ino);
	return status;
}

nfsstat4 nfs_op_close(struct nfs_cxn *cxn, const CLOSE4args *args,
		      struct list_head *writes, struct rpc_write **wr)
{
	nfsstat4 status = NFS4_OK;
	struct nfs_stateid sid;
	struct nfs_openfile *of = NULL;
	struct nfs_inode *ino = NULL;

	cxn->drc_mask |= drc_close;

	copy_sid(&sid, &args->open_stateid);

	if (debugging)
		applog(LOG_INFO, "op CLOSE (SEQ:%u SID.SEQ:%u SID.ID:%x)",
		       args->seqid, sid.seqid, sid.id);

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

	of->owner->cli_next_seq++;

	openfile_trash(of, false);

	/* really only for completeness */
	of->my_seq++;
	sid.seqid = of->my_seq;

out:
	WR32(status);
	if (status == NFS4_OK)
		WRSID(&sid);
	inode_free(ino);
	return status;
}

