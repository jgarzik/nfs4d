#ifndef __NFS4_COMPAT_H__
#define __NFS4_COMPAT_H__

#include <nfs4d-config.h>

#ifndef HAVE_XDR_U_QUAD_T
#define xdr_u_quad_t(a,b) xdr_u_hyper(a,b)
#define xdr_quad_t(a,b) xdr_hyper(a,b)
#endif

#endif /* __NFS4_COMPAT_H__ */
