/*
 * Please do not edit this file.
 * It was generated using rpcgen.
 */

#ifndef _FSDB_XDR_H_RPCGEN
#define _FSDB_XDR_H_RPCGEN

#include <rpc/rpc.h>

#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif


typedef int int32_t;

typedef u_int uint32_t;

typedef quad_t int64_t;

typedef u_quad_t uint64_t;
#define NFS_VERIFIER_SIZE 8
#define NFS_OPAQUE_LIMIT 1024

typedef uint64_t fsdb_client_id;

struct fsdb_client {
	fsdb_client_id id;
	uint32_t flags;
	uint32_t sequence_id;
	char verifier[NFS_VERIFIER_SIZE];
	struct {
		u_int owner_len;
		char *owner_val;
	} owner;
};
typedef struct fsdb_client fsdb_client;

/* the xdr functions */

#if defined(__STDC__) || defined(__cplusplus)
extern  bool_t xdr_int32_t (XDR *, int32_t*);
extern  bool_t xdr_uint32_t (XDR *, uint32_t*);
extern  bool_t xdr_int64_t (XDR *, int64_t*);
extern  bool_t xdr_uint64_t (XDR *, uint64_t*);
extern  bool_t xdr_fsdb_client_id (XDR *, fsdb_client_id*);
extern  bool_t xdr_fsdb_client (XDR *, fsdb_client*);

#else /* K&R C */
extern bool_t xdr_int32_t ();
extern bool_t xdr_uint32_t ();
extern bool_t xdr_int64_t ();
extern bool_t xdr_uint64_t ();
extern bool_t xdr_fsdb_client_id ();
extern bool_t xdr_fsdb_client ();

#endif /* K&R C */

#ifdef __cplusplus
}
#endif

#endif /* !_FSDB_XDR_H_RPCGEN */