
#include <syslog.h>
#include <glib.h>
#include "nfs4_prot.h"
#include "server.h"

#define WRFH(fh)		wr_fh(writes, wr, (fh))

static void *wr_fh(struct list_head *writes, struct rpc_write **wr_io,
		   struct nfs_fh fh_in)
{
	struct nfs_buf nb;
	struct nfs_fh fh;

	fh.ino = htonl(fh_in.ino);
	fh.generation = htonl(fh_in.generation);

	nb.len = sizeof(fh);
	nb.val = (char *) &fh;

	return wr_buf(writes, wr_io, &nb);
}

int nfs_fh_decode(const struct nfs_buf *fh_in, struct nfs_fh *fh_out)
{
	uint32_t *p;
	struct nfs_fh fh;

	if (!fh_in)
		return 0;
	if (fh_in->len != sizeof(fh))
		return 0;
	if (!fh_in->val)
		return 0;
	p = (void *) fh_in->val;

	fh.ino = ntohl(*p);
	p++;

	fh.generation = ntohl(*p);
	p++;

	if (!inode_fhget(fh))
		return -1;

	*fh_out = fh;
	return 1;
}

nfsstat4 nfs_op_getfh(struct nfs_cxn *cxn, struct curbuf *cur,
		      struct list_head *writes, struct rpc_write **wr)
{
	nfsstat4 status = NFS4_OK;
	bool printed = false;

	if (!inode_fhget(cxn->current_fh)) {
		status = NFS4ERR_NOFILEHANDLE;
		goto out;
	}

	if (debugging) {
		syslog(LOG_INFO, "op GETFH -> %u/%u",
			cxn->current_fh.ino,
			cxn->current_fh.generation);
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
	struct nfs_fh fh = { 0, };
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
		syslog(LOG_INFO, "op PUTFH (%u/%u)",
			fh.ino,
			fh.generation);

	WR32(status);
	return status;
}

nfsstat4 nfs_op_putrootfh(struct nfs_cxn *cxn, struct curbuf *cur,
		      struct list_head *writes, struct rpc_write **wr)
{
	struct nfs_inode *ino = __inode_get(INO_ROOT);

	fh_set(&cxn->current_fh, ino->ino, ino->generation);

	if (debugging)
		syslog(LOG_INFO, "op PUTROOTFH -> %u/%u",
			cxn->current_fh.ino,
			cxn->current_fh.generation);

	WR32(NFS4_OK);
	return NFS4_OK;
}

nfsstat4 nfs_op_putpubfh(struct nfs_cxn *cxn, struct curbuf *cur,
		      struct list_head *writes, struct rpc_write **wr)
{
	struct nfs_inode *ino = __inode_get(INO_ROOT);

	fh_set(&cxn->current_fh, ino->ino, ino->generation);

	if (debugging)
		syslog(LOG_INFO, "op PUTPUBFH -> %u/%u",
			cxn->current_fh.ino,
			cxn->current_fh.generation);

	WR32(NFS4_OK);
	return NFS4_OK;
}

nfsstat4 nfs_op_restorefh(struct nfs_cxn *cxn, struct curbuf *cur,
		      struct list_head *writes, struct rpc_write **wr)
{
	nfsstat4 status = NFS4_OK;
	bool printed = false;

	if (!inode_fhget(cxn->save_fh)) {
		status = NFS4ERR_RESTOREFH;
		goto out;
	}

	cxn->current_fh = cxn->save_fh;

	if (debugging) {
		syslog(LOG_INFO, "op RESTOREFH -> %u/%u",
			cxn->current_fh.ino,
			cxn->current_fh.generation);
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

	if (!inode_fhget(cxn->current_fh)) {
		status = NFS4ERR_NOFILEHANDLE;
		goto out;
	}

	cxn->save_fh = cxn->current_fh;

	if (debugging) {
		syslog(LOG_INFO, "op SAVEFH (SAVE:%u/%u)",
			cxn->save_fh.ino,
			cxn->save_fh.generation);
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

