
#include "nfs4-ram-config.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <memory.h>
#include <locale.h>
#include <argp.h>
#include <unistd.h>
#include <syslog.h>
#include <time.h>
#include <sys/time.h>
#include <rpc/pmap_clnt.h>
#include <netinet/in.h>
#include "server.h"
#include "nfs4_prot.h"


enum {
	LISTEN_SIZE		= 100,
};

struct timeval current_time;
GList *client_list = NULL;
int debugging = 0;
struct nfs_server srv;
static gboolean opt_foreground;
static unsigned int opt_nfs_port = 2049;

static const char doc[] =
"nfs4-ram - NFS4 server daemon";

static struct argp_option options[] = {
	{ "debug", 'd', NULL, 0,
	  "Enable debug output" },
	{ "foreground", 'f', NULL, 0,
	  "Run daemon in foreground" },
	{ "port", 'p', "PORT", 0,
	  "Bind to TCP port PORT (def. 2049)" },

	{ }
};

static error_t parse_opt (int key, char *arg, struct argp_state *state);
static const struct argp argp = { options, parse_opt, NULL, doc };

static void slerror(const char *prefix)
{
	syslog(LOG_ERR, "%s: %s", prefix, strerror(errno));
}

static void init_rng(void)
{
	unsigned long v;
	int fd;
	ssize_t bytes;

	fd = open("/dev/random", O_RDONLY);
	if (fd < 0) {
		slerror("/dev/random");
		goto srand_time;
	}

	bytes = read(fd, &v, sizeof(v));
	if (bytes < 0)
		slerror("/dev/random read");

	close(fd);

	if (bytes < sizeof(v))
		goto srand_time;

	srand48_r(v, &srv.rng);
	return;

srand_time:
	srand48_r(getpid() ^ time(NULL), &srv.rng);
}

static int init_sock(void)
{
	int sock, val;
	struct sockaddr_in saddr;

	sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock < 0) {
		slerror("socket");
		return -1;
	}

	val = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &val,
		       sizeof(val)) < 0) {
		slerror("setsockopt");
		return -1;
	}

	memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(opt_nfs_port);
	saddr.sin_addr.s_addr = htonl(INADDR_ANY);
	if (bind(sock, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
		slerror("bind");
		return -1;
	}

	if (listen(sock, LISTEN_SIZE) < 0) {
		slerror("listen");
		return -1;
	}

	return sock;
}

static void
nfs4_program_4(struct svc_req *rqstp, register SVCXPRT *transp)
{
	COMPOUND4args argument;
	COMPOUND4res result;
	bool_t retval;
	xdrproc_t _xdr_argument, _xdr_result;
	bool_t (*local)(char *, void *, struct svc_req *);
	struct timezone tz = { 0, 0 };

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
		syslog(LOG_ERR, "RPC: unknown proc %u",
			(unsigned int) rqstp->rq_proc);
		svcerr_noproc (transp);
		return;
	}
	memset ((char *)&argument, 0, sizeof (argument));
	if (!svc_getargs(transp, (xdrproc_t) _xdr_argument,
			 (caddr_t) &argument)) {
		syslog(LOG_ERR, "RPC: getargs failed");
		svcerr_decode (transp);
		return;
	}

	gettimeofday(&current_time, &tz);

	retval = (bool_t) (*local)((char *)&argument, (void *)&result, rqstp);

	if (retval > 0 && !svc_sendreply(transp, (xdrproc_t) _xdr_result, (char *)&result)) {
		svcerr_systemerr (transp);
	}
	if (!svc_freeargs (transp, (xdrproc_t) _xdr_argument, (caddr_t) &argument)) {
		syslog(LOG_ERR, "unable to free arguments");
		exit (1);
	}
	if (rqstp->rq_proc == NFSPROC4_COMPOUND)
		if (!nfs4_program_4_freeresult (transp, _xdr_result, &result))
			syslog(LOG_ERR, "unable to free results");
}

/* Linux is missing this prototype */
#if 0
bool_t gssrpc_pmap_unset(u_long prognum, u_long versnum);
#endif

static int init_rpc(int sock)
{
	register SVCXPRT *transp;

	transp = svctcp_create(sock, 0, 0);
	if (transp == NULL) {
		syslog(LOG_ERR, "cannot create tcp service.");
		return -1;
	}
	if (!svc_register(transp, NFS4_PROGRAM, NFS_V4, nfs4_program_4, IPPROTO_TCP)) {
		syslog(LOG_ERR, "unable to register (NFS4_PROGRAM, NFS_V4, tcp).");
		return -1;
	}

	return 0;
}

static int init_server(void)
{
	struct timezone tz = { 0, 0 };
	int sock;

	pmap_unset (NFS4_PROGRAM, NFS_V4);

	memset(&srv, 0, sizeof(srv));
	srv.lease_time = 5 * 60;
	srv.client_ids = g_hash_table_new_full(clientid_hash, clientid_equal,
					       NULL, NULL);
	srv.clid_idx = g_hash_table_new_full(g_direct_hash, g_direct_equal,
					     NULL, NULL);
	srv.state = g_hash_table_new_full(g_direct_hash, g_direct_equal,
					  NULL, state_free);

	if (gettimeofday(&current_time, &tz) < 0) {
		slerror("gettimeofday(2)");
		return -1;
	}

	if (!srv.client_ids || !srv.clid_idx || !srv.state) {
		syslog(LOG_ERR, "OOM in init_server()");
		return -1;
	}

	inode_table_init();

	init_rng();
	rand_verifier(&srv.instance_verf);

	sock = init_sock();
	if (sock < 0)
		return -1;

	if (init_rpc(sock) < 0)
		return -1;

	return 0;
}

static error_t parse_opt (int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'd':
		debugging = 1;
		break;
	case 'f':
		opt_foreground = TRUE;
		break;
	case 'p':
		if (atoi(arg) > 0 && atoi(arg) < 65536)
			opt_nfs_port = atoi(arg);
		else {
			fprintf(stderr, "invalid NFS port %s\n", arg);
			argp_usage(state);
		}
		break;

	case ARGP_KEY_ARG:
		argp_usage(state);	/* too many args */
		break;

	case ARGP_KEY_END:
		break;

	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

static void term_signal(int signal)
{
	syslog(LOG_INFO, "got termination signal");
	exit(1);
}

int main (int argc, char *argv[])
{
	error_t rc;

	setlocale(LC_ALL, "");

	rc = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (rc) {
		fprintf(stderr, "argp_parse failed: %s\n", strerror(rc));
		return 1;
	}

	signal(SIGHUP, SIG_IGN);
	signal(SIGINT, term_signal);
	signal(SIGTERM, term_signal);

	openlog("nfs4_ramd", LOG_PID, LOG_LOCAL2);

	if ((!opt_foreground) && (daemon(0, 0) < 0)) {
		slerror("daemon(2)");
		return 1;
	}

	if (init_server())
		return 1;

	syslog(LOG_INFO, PACKAGE_STRING " initialized%s",
	       debugging ? " (DEBUG MODE)" : "");

	svc_run ();

	syslog(LOG_ERR, "svc_run returned");
	return 1;
}

