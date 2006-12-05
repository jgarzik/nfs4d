
#include "server.h"

bool_t nfs_op_open(struct nfs_client *cli, OPEN4args *args, COMPOUND4res *cres)
{
	struct nfs_resop4 resop;
	OPEN4res *res;
	OPEN4resok *resok;
	nfsstat4 status = NFS4_OK, lu_stat;
	struct nfs_inode *dir_ino, *ino = NULL;
	struct nfs_dirent *de;
	struct nfs_state *st;
	int creating;

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
	status = dir_curfh(cli, &dir_ino);
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

	if (ino &&
	    ((args->share_access & ino->share_deny) ||
	     (args->share_deny & ino->share_access))) {
		status = NFS4ERR_DENIED;
		goto out;
	}

	/*
	 * look up shorthand client id (clientid4)
	 */
	st = g_hash_table_lookup(srv.clid_idx, &args->owner.clientid);
	if (!st) {
		status = NFS4ERR_BADOWNER;
		goto out;
	}

	status = NFS4ERR_NOTSUPP;

out:
	res->status = status;
	return push_resop(cres, &resop, status);
}

