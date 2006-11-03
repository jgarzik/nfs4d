#include <rpc/xdr.h>
#include <glib.h>
#include "nfs4_prot.h"
#include "server.h"

enum {
	FATTR_LAST		= FATTR4_MOUNTED_ON_FILEID,
};

#define FATTR_DEFINE(a,b,c)				\
	if (bitmap & ( 1ULL << FATTR4_##a )) {		\
		if (!xdr_fattr4_##b(&xdr, &attr->b)) {	\
			rc = FALSE;			\
			goto out;			\
		}					\
	}

bool_t fattr_parse(fattr4 *raw, struct nfs_fattr_set *attr)
{
	uint64_t bitmap = 0;
	XDR xdr;
	bool_t rc = TRUE;

	memset(attr, 0, sizeof(*attr));
	if (raw->attrmask.bitmap4_len > 0)
		bitmap = raw->attrmask.bitmap4_val[0];
	if (raw->attrmask.bitmap4_len > 1)
		bitmap |= ((uint64_t)raw->attrmask.bitmap4_val[1]) << 32;
	attr->bitmap = bitmap;

	/* raw->attr_vals.attrlist4_val; */

	memset(&xdr, 0, sizeof(xdr));
	xdrmem_create(&xdr, raw->attr_vals.attrlist4_val,
		      raw->attr_vals.attrlist4_len, XDR_DECODE);

#include "fattr.h"

out:
	xdr_destroy(&xdr);
	return rc;
}

#undef FATTR_DEFINE

void fattr_free(struct nfs_fattr_set *attr)
{
}

