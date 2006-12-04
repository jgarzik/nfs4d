
#include "server.h"

bool_t nfs_op_open(struct nfs_client *cli, COMPOUND4res *cres)
{
	struct nfs_resop4 resop;
	OPEN4res *res;
	OPEN4resok *resok;
	nfsstat4 status = NFS4_OK;

	memset(&resop, 0, sizeof(resop));
	resop.resop = OP_OPEN;
	res = &resop.nfs_resop4_u.opopen;
	resok = &res->OPEN4res_u.resok4;

	status = NFS4ERR_NOTSUPP;

out:
	res->status = status;
	return push_resop(cres, &resop, status);
}

