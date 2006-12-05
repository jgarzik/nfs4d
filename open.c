
#include "server.h"

bool_t nfs_op_open(struct nfs_client *cli, OPEN4args *args, COMPOUND4res *cres)
{
	struct nfs_resop4 resop;
	OPEN4res *res;
	OPEN4resok *resok;
	nfsstat4 status = NFS4_OK, lu_stat;
	struct nfs_inode *dir_ino, *ino = NULL;
	struct nfs_dirent *de;

	memset(&resop, 0, sizeof(resop));
	resop.resop = OP_OPEN;
	res = &resop.nfs_resop4_u.opopen;
	resok = &res->OPEN4res_u.resok4;

	if (args->claim.claim != CLAIM_NULL) {
		status = NFS4ERR_NOTSUPP;
		goto out;
	}

	status = dir_curfh(cli, &dir_ino);
	if (status != NFS4_OK)
		goto out;

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

	/* does the dirent's existence match our expectations? */
	if ((args->openhow.opentype == OPEN4_NOCREATE) &&
	    (lu_stat == NFS4ERR_NOENT)) {
		status = lu_stat;
		goto out;
	}
	if ((lu_stat == NFS4_OK) && (args->openhow.opentype == OPEN4_CREATE) &&
	    (args->openhow.openflag4_u.how.mode != UNCHECKED4)) {
		status = NFS4ERR_EXIST;
		goto out;
	}

	status = NFS4ERR_NOTSUPP;

out:
	res->status = status;
	return push_resop(cres, &resop, status);
}

