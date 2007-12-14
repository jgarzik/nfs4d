
#include <syslog.h>
#include <glib.h>
#include "nfs4_prot.h"
#include "server.h"

#define WRFH(fh)		wr_fh(writes, wr, (fh))

static void *wr_fh(struct list_head *writes, struct rpc_write **wr_io,
		   nfsino_t fh_in)
{
	struct nfs_buf nb;
	uint32_t fh = htonl(fh_in);

	nb.len = sizeof(fh);
	nb.val = (char *) &fh;

	return wr_buf(writes, wr_io, &nb);
}

int nfs_fh_decode(const struct nfs_buf *fh_in, nfsino_t *fh_out)
{
	nfsino_t *fhp;
	nfsino_t fh;

	if (!fh_in)
		return 0;
	if (fh_in->len != sizeof(nfsino_t))
		return 0;
	if (!fh_in->val)
		return 0;
	fhp = (void *) fh_in->val;
	fh = ntohl(*fhp);

	if (!inode_get(fh))
		return -1;

	*fh_out = fh;
	return 1;
}

nfsstat4 nfs_op_getfh(struct nfs_cxn *cxn, struct curbuf *cur,
		      struct list_head *writes, struct rpc_write **wr)
{
	nfsstat4 status = NFS4_OK;
	bool printed = false;

	if (!inode_get(cxn->current_fh)) {
		status = NFS4ERR_NOFILEHANDLE;
		goto out;
	}

	if (debugging) {
		syslog(LOG_INFO, "op GETFH -> %u", cxn->current_fh);
		printed = true;
	}

out:
	if (!printed) {
		if (debugging)
			syslog(LOG_INFO, "op GETFH");
	}

	WR32(status);
	if (status == NFS4_OK)
		WRFH(cxn->current_fh);
	return status;
}

nfsstat4 nfs_op_putfh(struct nfs_cxn *cxn, struct curbuf *cur,
		      struct list_head *writes, struct rpc_write **wr)
{
	nfsstat4 status = NFS4_OK;
	nfsino_t fh = 0;
	struct nfs_buf nb;
	int rc;

	CURBUF(&nb);			/* opaque filehandle */

	rc = nfs_fh_decode(&nb, &fh);
	if (rc == 0)
		status = NFS4ERR_BADHANDLE;
	else if (rc < 0)
		status = NFS4ERR_STALE;
	else
		cxn->current_fh = fh;

	if (debugging)
		syslog(LOG_INFO, "op PUTFH (%u)", fh);

	WR32(status);
	return status;
}

nfsstat4 nfs_op_putrootfh(struct nfs_cxn *cxn, struct curbuf *cur,
		      struct list_head *writes, struct rpc_write **wr)
{
	cxn->current_fh = INO_ROOT;

	if (debugging)
		syslog(LOG_INFO, "op PUTROOTFH -> %u", cxn->current_fh);

	WR32(NFS4_OK);
	return NFS4_OK;
}

nfsstat4 nfs_op_putpubfh(struct nfs_cxn *cxn, struct curbuf *cur,
		      struct list_head *writes, struct rpc_write **wr)
{
	cxn->current_fh = INO_ROOT;

	if (debugging)
		syslog(LOG_INFO, "op PUTPUBFH -> %u", cxn->current_fh);

	WR32(NFS4_OK);
	return NFS4_OK;
}

nfsstat4 nfs_op_restorefh(struct nfs_cxn *cxn, struct curbuf *cur,
		      struct list_head *writes, struct rpc_write **wr)
{
	nfsstat4 status = NFS4_OK;
	bool printed = false;

	if (!inode_get(cxn->save_fh)) {
		status = NFS4ERR_RESTOREFH;
		goto out;
	}

	cxn->current_fh = cxn->save_fh;

	if (debugging) {
		syslog(LOG_INFO, "op RESTOREFH -> %u", cxn->current_fh);
		printed = true;
	}

out:
	if (!printed) {
		if (debugging)
			syslog(LOG_INFO, "op RESTOREFH");
	}

	WR32(status);
	return status;
}

nfsstat4 nfs_op_savefh(struct nfs_cxn *cxn, struct curbuf *cur,
		       struct list_head *writes, struct rpc_write **wr)
{
	nfsstat4 status = NFS4_OK;
	bool printed = false;

	if (!inode_get(cxn->current_fh)) {
		status = NFS4ERR_NOFILEHANDLE;
		goto out;
	}

	cxn->save_fh = cxn->current_fh;

	if (debugging) {
		syslog(LOG_INFO, "op SAVEFH (SAVE:%u)", cxn->save_fh);
		printed = true;
	}

out:
	if (!printed) {
		if (debugging)
			syslog(LOG_INFO, "op SAVEFH");
	}

	WR32(status);
	return status;
}

