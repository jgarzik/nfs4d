/*
 * Please do not edit this file.
 * It was generated using rpcgen.
 */

#include "fsdb_xdr.h"

#if 0
bool_t
xdr_int32_t (XDR *xdrs, int32_t *objp)
{
	register int32_t *buf;

	 if (!xdr_int (xdrs, objp))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_uint32_t (XDR *xdrs, uint32_t *objp)
{
	register int32_t *buf;

	 if (!xdr_u_int (xdrs, objp))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_int64_t (XDR *xdrs, int64_t *objp)
{
	register int32_t *buf;

	 if (!xdr_quad_t (xdrs, objp))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_uint64_t (XDR *xdrs, uint64_t *objp)
{
	register int32_t *buf;

	 if (!xdr_u_quad_t (xdrs, objp))
		 return FALSE;
	return TRUE;
}
#endif

bool_t
xdr_fsdb_client_id (XDR *xdrs, fsdb_client_id *objp)
{

	 if (!xdr_uint64_t (xdrs, objp))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_fsdb_client (XDR *xdrs, fsdb_client *objp)
{

	 if (!xdr_fsdb_client_id (xdrs, &objp->id))
		 return FALSE;
	 if (!xdr_uint32_t (xdrs, &objp->flags))
		 return FALSE;
	 if (!xdr_uint32_t (xdrs, &objp->sequence_id))
		 return FALSE;
	 if (!xdr_opaque (xdrs, objp->verifier, NFS_VERIFIER_SIZE))
		 return FALSE;
	 if (!xdr_bytes (xdrs, (char **)&objp->owner.owner_val, (u_int *) &objp->owner.owner_len, NFS_OPAQUE_LIMIT))
		 return FALSE;
	return TRUE;
}
