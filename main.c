/*
 * Please do not edit this file.
 * It was generated using rpcgen.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "server.h"
#include "nfs4_prot.h"

static enum auth_stat check_auth(struct svc_req *rqstp)
{
	switch (rqstp->rq_cred.oa_flavor) {
	case AUTH_UNIX:
		return AUTH_OK;
	default:
		return AUTH_TOOWEAK;
	}

	return AUTH_FAILED;	/* never reached; kill warning */
}

static void
nfs4_program_4(struct svc_req *rqstp, register SVCXPRT *transp)
{
	COMPOUND4args argument;
	COMPOUND4res result;
	bool_t retval;
	xdrproc_t _xdr_argument, _xdr_result;
	bool_t (*local)(char *, void *, struct svc_req *);
	enum auth_stat auth_stat;

	switch (rqstp->rq_proc) {
	case NFSPROC4_NULL:
		_xdr_argument = (xdrproc_t) xdr_void;
		_xdr_result = (xdrproc_t) xdr_void;
		local = (bool_t (*) (char *, void *,  struct svc_req *))nfsproc4_null_4_svc;
		break;

	case NFSPROC4_COMPOUND:
		_xdr_argument = (xdrproc_t) xdr_COMPOUND4args;
		_xdr_result = (xdrproc_t) xdr_COMPOUND4res;
		local = (bool_t (*) (char *, void *,  struct svc_req *))nfsproc4_compound_4_svc;
		break;

	default:
		svcerr_noproc (transp);
		return;
	}
	memset ((char *)&argument, 0, sizeof (argument));
	if (!svc_getargs (transp, (xdrproc_t) _xdr_argument, (caddr_t) &argument)) {
		svcerr_decode (transp);
		return;
	}

	auth_stat = check_auth(rqstp);
	if (auth_stat != AUTH_OK) {
		retval = FALSE;
		svcerr_auth(transp, auth_stat);
	} else
		retval = (bool_t) (*local)((char *)&argument,
					   (void *)&result, rqstp);

	if (retval > 0 && !svc_sendreply(transp, (xdrproc_t) _xdr_result, (char *)&result)) {
		svcerr_systemerr (transp);
	}
	if (!svc_freeargs (transp, (xdrproc_t) _xdr_argument, (caddr_t) &argument)) {
		fprintf (stderr, "%s", "unable to free arguments");
		exit (1);
	}
	if (!nfs4_program_4_freeresult (transp, _xdr_result, &result))
		fprintf (stderr, "%s", "unable to free results");

	return;
}

/* Linux is missing this prototype */
bool_t gssrpc_pmap_unset(u_long prognum, u_long versnum);

int
main (int argc, char **argv)
{
	register SVCXPRT *transp;

	pmap_unset (NFS4_PROGRAM, NFS_V4);

	transp = svctcp_create(RPC_ANYSOCK, 0, 0);
	if (transp == NULL) {
		fprintf (stderr, "%s", "cannot create tcp service.");
		exit(1);
	}
	if (!svc_register(transp, NFS4_PROGRAM, NFS_V4, nfs4_program_4, IPPROTO_TCP)) {
		fprintf (stderr, "%s", "unable to register (NFS4_PROGRAM, NFS_V4, tcp).");
		exit(1);
	}

	inode_table_init();

	svc_run ();
	fprintf (stderr, "%s", "svc_run returned");
	exit (1);
	/* NOTREACHED */
}
