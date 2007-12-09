
#include <syslog.h>
#include <glib.h>
#include "nfs4_prot.h"
#include "server.h"

void nfs_fh_set(nfs_fh4 *fh, nfsino_t fh_int)
{
	nfsino_t *fh_val = g_slice_new(nfsino_t);
	*fh_val = GUINT32_TO_BE(fh_int);

	fh->nfs_fh4_len = sizeof(nfsino_t);
	fh->nfs_fh4_val = (char *)(void *) fh_val;
}

static void nfs_fh_free(nfs_fh4 *fh)
{
	if (fh) {
		nfsino_t *fh_val = (void *) fh->nfs_fh4_val;
		g_slice_free(nfsino_t, fh_val);
		fh->nfs_fh4_val = NULL;
	}
}

nfsino_t nfs_fh_decode(const nfs_fh4 *fh_in)
{
	nfsino_t *fhp;
	nfsino_t fh;

	if (!fh_in)
		return 0;
	if (fh_in->nfs_fh4_len != sizeof(nfsino_t))
		return 0;
	if (!fh_in->nfs_fh4_val)
		return 0;
	fhp = (void *) fh_in->nfs_fh4_val;
	fh = GUINT32_FROM_BE(*fhp);

	if (!inode_get(fh))
		return 0;

	return fh;
}

void nfs_getfh_free(GETFH4res *opgetfh)
{
	nfs_fh_free(&opgetfh->GETFH4res_u.resok4.object);
}

bool_t nfs_op_getfh(struct nfs_cxn *cxn, COMPOUND4res *cres)
{
	struct nfs_resop4 resop;
	GETFH4res *res;
	GETFH4resok *resok;
	nfsstat4 status = NFS4_OK;

	if (debugging)
		syslog(LOG_INFO, "op GETFH");

	memset(&resop, 0, sizeof(resop));
	resop.resop = OP_GETFH;
	res = &resop.nfs_resop4_u.opgetfh;
	resok = &res->GETFH4res_u.resok4;

	if (debugging)
		syslog(LOG_INFO, "CURRENT_FH == %u", cxn->current_fh);

	if (!inode_get(cxn->current_fh)) {
		status = NFS4ERR_NOFILEHANDLE;
		goto out;
	}

	nfs_fh_set(&resok->object, cxn->current_fh);

out:
	res->status = status;
	return push_resop(cres, &resop, status);
}

bool_t nfs_op_putfh(struct nfs_cxn *cxn, PUTFH4args *arg, COMPOUND4res *cres)
{
	struct nfs_resop4 resop;
	PUTFH4res *res;
	nfsstat4 status = NFS4_OK;
	nfsino_t fh;

	memset(&resop, 0, sizeof(resop));
	resop.resop = OP_PUTFH;
	res = &resop.nfs_resop4_u.opputfh;

	fh = nfs_fh_decode(&arg->object);
	if (!fh) {
		if (debugging)
			syslog(LOG_INFO, "op PUTFH (BAD)");
		status = NFS4ERR_BADHANDLE;
		goto out;
	}

	if (debugging)
		syslog(LOG_INFO, "op PUTFH (%u)", fh);

	cxn->current_fh = fh;

out:
	res->status = status;
	return push_resop(cres, &resop, status);
}

bool_t nfs_op_putrootfh(struct nfs_cxn *cxn, COMPOUND4res *cres)
{
	struct nfs_resop4 resop;
	PUTFH4res *res;
	nfsstat4 status = NFS4_OK;

	if (debugging)
		syslog(LOG_INFO, "op PUTROOTFH");

	memset(&resop, 0, sizeof(resop));
	resop.resop = OP_PUTROOTFH;
	res = &resop.nfs_resop4_u.opputfh;

	cxn->current_fh = INO_ROOT;

	res->status = status;
	return push_resop(cres, &resop, status);
}

bool_t nfs_op_putpubfh(struct nfs_cxn *cxn, COMPOUND4res *cres)
{
	struct nfs_resop4 resop;
	PUTFH4res *res;
	nfsstat4 status = NFS4_OK;

	if (debugging)
		syslog(LOG_INFO, "op PUTPUBFH");

	memset(&resop, 0, sizeof(resop));
	resop.resop = OP_PUTPUBFH;
	res = &resop.nfs_resop4_u.opputfh;

	cxn->current_fh = INO_ROOT;

	res->status = status;
	return push_resop(cres, &resop, status);
}

bool_t nfs_op_restorefh(struct nfs_cxn *cxn, COMPOUND4res *cres)
{
	struct nfs_resop4 resop;
	RESTOREFH4res *res;
	nfsstat4 status = NFS4_OK;

	if (debugging)
		syslog(LOG_INFO, "op RESTOREFH");

	memset(&resop, 0, sizeof(resop));
	resop.resop = OP_RESTOREFH;
	res = &resop.nfs_resop4_u.oprestorefh;

	if (!inode_get(cxn->save_fh)) {
		status = NFS4ERR_RESTOREFH;
		goto out;
	}

	cxn->current_fh = cxn->save_fh;

out:
	res->status = status;
	return push_resop(cres, &resop, status);
}

bool_t nfs_op_savefh(struct nfs_cxn *cxn, COMPOUND4res *cres)
{
	struct nfs_resop4 resop;
	SAVEFH4res *res;
	nfsstat4 status = NFS4_OK;

	if (debugging)
		syslog(LOG_INFO, "op SAVEFH");

	memset(&resop, 0, sizeof(resop));
	resop.resop = OP_SAVEFH;
	res = &resop.nfs_resop4_u.opsavefh;

	if (!inode_get(cxn->current_fh)) {
		status = NFS4ERR_NOFILEHANDLE;
		goto out;
	}

	cxn->save_fh = cxn->current_fh;

out:
	res->status = status;
	return push_resop(cres, &resop, status);
}

