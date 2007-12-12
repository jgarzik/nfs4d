
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

struct conflict_fe_state {
	OPEN4args *args;
	nfsino_t ino;
	gboolean match;
};

static void state_sh_conflict(gpointer key, gpointer val, gpointer user_data)
{
	struct nfs_state *st = val;
	struct conflict_fe_state *cfs = user_data;

	if (st->ino != cfs->ino)
		return;
	if (st->flags & (stfl_dead | stfl_lock))
		return;

	if (cfs->args->share_access & st->share_dn)
		cfs->match = TRUE;

	if (cfs->args->share_deny & st->share_ac)
		cfs->match = TRUE;
}

bool_t nfs_op_open(struct nfs_cxn *cxn, OPEN4args *args, COMPOUND4res *cres)
{
	struct nfs_resop4 resop;
	OPEN4res *res;
	OPEN4resok *resok;
	nfsstat4 status = NFS4_OK, lu_stat;
	struct nfs_inode *dir_ino, *ino = NULL;
	struct nfs_dirent *de;
	struct nfs_client *cli;
	struct nfs_state *st;
	struct nfs_stateid *sid;
	gboolean creating, recreating = FALSE;

	print_open_args(args);

	memset(&resop, 0, sizeof(resop));
	resop.resop = OP_OPEN;
	res = &resop.nfs_resop4_u.opopen;
	resok = &res->OPEN4res_u.resok4;

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
	lu_stat = dir_lookup(dir_ino, &args->claim.open_claim4_u.file, &de);
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
		creating = FALSE;
		recreating = TRUE;
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
		struct conflict_fe_state cfs = { args, ino->ino, FALSE };

		g_hash_table_foreach(srv.state, state_sh_conflict, &cfs);

		if (cfs.match) {
			status = NFS4ERR_SHARE_DENIED;
			goto out;
		}
	}

	/*
	 * look up shorthand client id (clientid4)
	 */
	cli = g_hash_table_lookup(srv.clid_idx, &args->owner.clientid);
	if (!cli) {
		status = NFS4ERR_BADOWNER;
		goto out;
	}
	if (!cli->id) {
		status = NFS4ERR_STALE_CLIENTID;
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

		status = inode_add(dir_ino, ino,
		   &args->openhow.openflag4_u.how.createhow4_u.createattrs,
		   &args->claim.open_claim4_u.file,
		   &resok->attrset, &resok->cinfo);
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
		uint64_t bitmap_set = 0;
		args->openhow.openflag4_u.how.createhow4_u.createattrs.attrmask.bitmap4_val[0]
			&= GUINT32_TO_BE(1 << FATTR4_SIZE);
		args->openhow.openflag4_u.how.createhow4_u.createattrs.attrmask.bitmap4_val[1] = 0;

		status = inode_apply_attrs(ino,
			&args->openhow.openflag4_u.how.createhow4_u.createattrs,
			&bitmap_set, NULL, FALSE);
		if (status != NFS4_OK)
			goto out;
	}

	st = calloc(1, sizeof(struct nfs_state));
	st->cli = cli;
	st->id = gen_stateid();
	st->owner = strndup(args->owner.owner.owner_val,
			    args->owner.owner.owner_len);
	st->ino = ino->ino;
	st->share_ac = args->share_access;
	st->share_dn = args->share_deny;
	st->seq = args->seqid;

	g_hash_table_insert(srv.state, GUINT_TO_POINTER(st->id), st);

	sid = (struct nfs_stateid *) &resok->stateid;
	sid->seqid = args->seqid;
	sid->id = GUINT32_TO_LE(st->id);
	memcpy(&sid->server_verf, &srv.instance_verf,
	       sizeof(srv.instance_verf));
	resok->rflags = OPEN4_RESULT_LOCKTYPE_POSIX;
	resok->delegation.delegation_type = OPEN_DELEGATE_NONE;

	status = NFS4_OK;
	cxn->current_fh = ino->ino;

	if (debugging)
		syslog(LOG_INFO, "   OPEN -> (SEQ:%u ID:%x)",
		       sid->seqid, st->id);

out:
	res->status = status;
	return push_resop(cres, &resop, status);
}

bool_t nfs_op_open_confirm(struct nfs_cxn *cxn, OPEN_CONFIRM4args *arg, COMPOUND4res *cres)
{
	struct nfs_resop4 resop;
	OPEN_CONFIRM4res *res;
	OPEN_CONFIRM4resok *resok;
	nfsstat4 status = NFS4_OK;
	struct nfs_stateid *sid = (struct nfs_stateid *) &arg->open_stateid;
	uint32_t id = GUINT32_FROM_LE(sid->id);
	struct nfs_state *st = NULL;
	struct nfs_inode *ino;

	if (debugging)
		syslog(LOG_INFO, "op OPEN_CONFIRM (SEQ:%u ID:%x)",
		       arg->seqid, id);

	memset(&resop, 0, sizeof(resop));
	resop.resop = OP_OPEN_CONFIRM;
	res = &resop.nfs_resop4_u.opopen_confirm;
	resok = &res->OPEN_CONFIRM4res_u.resok4;

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

	status = stateid_lookup(id, &st);
	if (status != NFS4_OK)
		goto out;

	if (cxn->current_fh != st->ino) {
		status = NFS4ERR_NOFILEHANDLE;
		goto out;
	}

	if (arg->seqid != (st->seq + 1)) {
		status = NFS4ERR_BAD_SEQID;
		goto out;
	}

	sid = (struct nfs_stateid *) &resok->open_stateid;
	sid->seqid = arg->seqid;
	sid->id = GUINT32_TO_LE(st->id);
	memcpy(&sid->server_verf, &srv.instance_verf,
	       sizeof(srv.instance_verf));

out:
	res->status = status;
	return push_resop(cres, &resop, status);
}

bool_t nfs_op_close(struct nfs_cxn *cxn, CLOSE4args *arg, COMPOUND4res *cres)
{
	struct nfs_resop4 resop;
	CLOSE4res *res;
	nfsstat4 status = NFS4_OK;
	struct nfs_stateid *sid = (struct nfs_stateid *) &arg->open_stateid;
	uint32_t id = GUINT32_FROM_LE(sid->id);

	if (debugging)
		syslog(LOG_INFO, "op CLOSE (SEQ:%u ID:%x)",
		       arg->seqid, id);

	memset(&resop, 0, sizeof(resop));
	resop.resop = OP_CLOSE;
	res = &resop.nfs_resop4_u.opclose;

	if (!cxn->current_fh) {
		status = NFS4ERR_NOFILEHANDLE;
		goto out;
	}

	if (id) {
		struct nfs_state *st;

		status = stateid_lookup(id, &st);
		if (status != NFS4_OK)
			goto out;

		if (arg->seqid != (st->seq + 1)) {
			status = NFS4ERR_BAD_SEQID;
			goto out;
		}

		state_trash(st);
	}

	memcpy(&res->CLOSE4res_u.open_stateid,
	       &arg->open_stateid, sizeof(arg->open_stateid));

out:
	res->status = status;
	return push_resop(cres, &resop, status);
}

