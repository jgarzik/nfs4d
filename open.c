
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

	syslog(LOG_INFO, "   OPEN (SEQ:%u SHAC:%x SHDN:%x OCID:%Lx ON:%.*s "
	       "HOW:%s CLM:%s)",
	       args->seqid,
	       args->share_access,
	       args->share_deny,
	       (unsigned long long) args->owner.clientid,
	       args->owner.owner.owner_len,
	       args->owner.owner.owner_val,
	       args->openhow.opentype == OPEN4_CREATE ? "CR" : "NOC",
	       name_open_claim_type4[args->claim.claim]);
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

	if ((cfs->args->share_access & st->share_dn) ||
	    (cfs->args->share_deny & st->share_ac))
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
	int creating;

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

	/*
	 * does the dirent's existence match our expectations?
	 */
	if ((!creating) && (lu_stat == NFS4ERR_NOENT)) {
		status = lu_stat;
		goto out;
	}
	if ((lu_stat == NFS4_OK) && creating &&
	    (args->openhow.openflag4_u.how.mode != UNCHECKED4)) {
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

	/*
	 * create file, if necessary
	 */
	if (creating) {
		ino = inode_new_file();
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

	st = calloc(1, sizeof(struct nfs_state));
	st->cli = cli;
	st->id = gen_stateid();
	st->owner = strndup(args->owner.owner.owner_val,
			    args->owner.owner.owner_len);
	st->ino = ino->ino;
	st->share_ac = args->share_access;
	st->share_dn = args->share_deny;

	g_hash_table_insert(srv.state, GUINT_TO_POINTER(st->id), st);

	sid = (struct nfs_stateid *) &resok->stateid;
	sid->seqid = args->seqid + 1;
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

		state_trash(st);
	}

	memcpy(&res->CLOSE4res_u.open_stateid,
	       &arg->open_stateid, sizeof(arg->open_stateid));

out:
	res->status = status;
	return push_resop(cres, &resop, status);
}

