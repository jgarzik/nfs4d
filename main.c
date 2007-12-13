
#include "nfs4-ram-config.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <argp.h>
#include <locale.h>
#include <syslog.h>
#include <gnet.h>
#include <rpc/auth.h>
#include <rpc/rpc_msg.h>
#include "server.h"


enum {
	LISTEN_SIZE		= 100,

	TMOUT_READ_HDR		= 30 * 60 * 1000,	/* 30 min (units: ms) */
	TMOUT_READ		= 60 * 60 * 1000,	/* 60 min (units: ms) */

	MAX_FRAG_SZ		= 50 * 1024 * 1024,	/* arbitrary */
	MAX_MSG_SZ		= MAX_FRAG_SZ,

	HDR_FRAG_END		= (1U << 31),
};

struct timeval current_time;
int debugging = 0;
struct nfs_server srv;
static bool opt_foreground;
static unsigned int opt_nfs_port = 2049;
static GServer *tcpsrv;

static const char doc[] =
"nfs4-ram - NFS4 server daemon";

enum rpc_cxn_state {
	get_hdr,
	get_data
};

struct rpc_cxn {
	struct nfs_server	*server;

	GConn			*conn;

	enum rpc_cxn_state	state;

	void			*msg;
	unsigned int		msg_len;
	unsigned int		next_frag;
	bool			last_frag;
};

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

void *cur_skip(struct curbuf *cur, unsigned int n)
{
	void *buf = cur->buf;

	if (!n || n > cur->len)
		return NULL;

	cur->buf += n;
	cur->len -= n;

	return buf;
}

uint32_t cur_read32(struct curbuf *cur)
{
	uint32_t *p = cur_skip(cur, 4);
	if (p)
		return ntohl(*p);

	return 0;
}

uint64_t cur_read64(struct curbuf *cur)
{
	uint64_t v[2];

	if (cur->len < 8)
		return 0;

	v[0] = cur_read32(cur);
	v[1] = cur_read32(cur);

	return (v[0] << 32) | v[1];
}

uint64_t cur_readmap(struct curbuf *cur)
{
	uint32_t len;
	uint64_t val = 0;

	if (cur->len < 4)
		return 0;

	len = cur_read32(cur);
	if (len) {
		val = cur_read32(cur);
		len--;
	}
	if (len) {
		val |= ((uint64_t)cur_read32(cur)) << 32;
		len--;
	}
	while (len) {
		cur_read32(cur);
		len--;
	}

	return val;
}

void *cur_readmem(struct curbuf *cur, unsigned int n)
{
	if (!n)
		return NULL;

	return cur_skip(cur, XDR_QUADLEN(n) * 4);
}

void cur_readbuf(struct curbuf *cur, struct nfs_buf *nb)
{
	nb->len = cur_read32(cur);
	if (!nb->len)
		nb->val = NULL;
	else
		nb->val = cur_readmem(cur, nb->len);
}

void cur_readsid(struct curbuf *cur, struct nfs_stateid *sid)
{
	void *verf;

	sid->seqid = cur_read32(cur);
	sid->id = cur_read32(cur);
	verf = cur_readmem(cur, sizeof(verifier4));
	if (verf)
		memcpy(sid, verf, sizeof(verifier4));
}

static unsigned int wr_free(struct rpc_write *wr)
{
	return RPC_WRITE_BUFSZ - wr->len;
}

void *wr_skip(struct list_head *writes, struct rpc_write **wr_io,
		     unsigned int n)
{
	struct rpc_write *wr = *wr_io;
	void *buf;

	if (n > wr_free(wr)) {
		wr = malloc(sizeof(*wr));
		if (!wr) {
			syslog(LOG_ERR, "OOM in wr_skip()");
			return NULL;
		}

		wr->len = 0;
		INIT_LIST_HEAD(&wr->node);
		list_add_tail(&wr->node, writes);
		*wr_io = wr;

		/* should never happen */
		if (n > wr_free(wr)) {
			syslog(LOG_ERR, "BUG in wr_skip()");
			return NULL;
		}
	}

	buf = wr->buf + wr->len;
	wr->len += n;

	return buf;
}

uint32_t *wr_write32(struct list_head *writes, struct rpc_write **wr_io,uint32_t val)
{
	uint32_t *p = wr_skip(writes, wr_io, 4);
	if (p)
		*p = htonl(val);
	return p;
}

uint64_t *wr_write64(struct list_head *writes, struct rpc_write **wr, uint64_t val)
{
	uint32_t *p = WR32(val >> 32);
	WR32(val);

	return (uint64_t *) p;
}

void *wr_mem(struct list_head *writes, struct rpc_write **wr_io,
	     const void *buf, unsigned int len)
{
	void *dst = wr_skip(writes, wr_io, len);
	if (dst)
		memcpy(dst, buf, len);
	return dst;
}

void *wr_buf(struct list_head *writes, struct rpc_write **wr_io,
		    const struct nfs_buf *nb)
{
	void *dst;

	if (!wr_write32(writes, wr_io, nb->len))
		return NULL;

	dst = wr_skip(writes, wr_io, XDR_QUADLEN(nb->len) * 4);
	if (dst)
		memcpy(dst, nb->val, nb->len);
	return dst;
}

void *wr_str(struct list_head *writes, struct rpc_write **wr_io, const char *s)
{
	struct nfs_buf nb;

	if (!s)
		return NULL;
	
	nb.len = strlen(s);
	nb.val = (void *) s;

	return wr_buf(writes, wr_io, &nb);
}

void *wr_sid(struct list_head *writes, struct rpc_write **wr_io,
	     const struct nfs_stateid *sid)
{
	void *p = wr_write32(writes, wr_io, sid->seqid);
	wr_write32(writes, wr_io, sid->id);
	wr_mem(writes, wr_io, &sid->server_verf, sizeof(verifier4));
	return p;
}

void *wr_map(struct list_head *writes, struct rpc_write **wr,
			uint64_t bitmap)
{
	uint64_t bitmap_hi = bitmap >> 32;
	uint32_t *p;

	p = WR32(2);
	if (!WR32(bitmap))
		return NULL;
	if (!WR32(bitmap_hi))
		return NULL;

	return p;
}

static void rpc_msg(struct rpc_cxn *rc, void *msg, unsigned int msg_len)
{
	struct timezone tz = { 0, 0 };
	struct curbuf _cur = { msg, msg, msg_len, msg_len };
	struct curbuf *cur = &_cur;
	uint32_t proc, xid;
	struct opaque_auth auth_cred, auth_verf;
	struct rpc_write *_wr, *iter, **wr;
	struct list_head _writes, *writes;

	_wr = NULL;
	wr = &_wr;
	writes = &_writes;
	INIT_LIST_HEAD(writes);

	gettimeofday(&current_time, &tz);

	/*
	 * decode RPC header
	 */

	xid = CR32();			/* xid */
	if (CR32() != CALL)		/* msg type */
		goto err_out;
	if ((CR32() != 2) ||		/* rpc version */
	    (CR32() != NFS4_PROGRAM) ||/* rpc program */
	    (CR32() != NFS_V4))	/* rpc program version */
		goto err_out;
	proc = CR32();

	auth_cred.oa_flavor = CR32();
	auth_cred.oa_length = CR32();
	auth_cred.oa_base = CURMEM(auth_cred.oa_length);
	auth_verf.oa_flavor = CR32();
	auth_cred.oa_length = CR32();
	auth_verf.oa_base = CURMEM(auth_cred.oa_length);

	if (!auth_cred.oa_base || !auth_verf.oa_base)
		goto err_out;

	/*
	 * begin the RPC response message
	 */
	_wr = malloc(sizeof(*wr));
	if (!_wr)
		goto err_out;

	list_add_tail(&_wr->node, writes);

	WR32(xid);
	WR32(REPLY);
	WR32(MSG_ACCEPTED);
	/* FIXME: write opaque_auth verf */
	WR32(SUCCESS);

	/*
	 * handle RPC call
	 */

	switch (proc) {
	case NFSPROC4_NULL:
		nfsproc_null(&auth_cred, &auth_verf, cur, writes, wr);
		break;
	case NFSPROC4_COMPOUND:
		nfsproc_compound(&auth_cred, &auth_verf, cur, writes, wr);
		break;
	default:
		goto err_out;
	}

	/*
	 * send response back to client asynchronously
	 * TODO: way too much alloc+copy
	 */

	list_for_each_entry_safe(_wr, iter, writes, node) {
		if (_wr->len)
			gnet_conn_write(rc->conn, _wr->buf, _wr->len);
		list_del(&_wr->node);
		free(_wr);
	}

	return;

err_out:
	/* FIXME: reply to bad XDR/RPC */
	return;
}

static void rpc_cxn_free(struct rpc_cxn *cxn)
{
	gnet_conn_unref(cxn->conn);
	free(cxn->msg);
}

static void rpc_cxn_event(GConn *conn, GConnEvent *evt, gpointer user_data)
{
	struct rpc_cxn *rc = user_data;
	uint32_t tmp;
	void *mem;

	switch (evt->type) {
	case GNET_CONN_ERROR:
	case GNET_CONN_CLOSE:
	case GNET_CONN_TIMEOUT:
		goto err_out;

	case GNET_CONN_READ:
		switch (rc->state) {
		case get_hdr:
			tmp = ntohl(*(uint32_t *)evt->buffer);
			if (tmp & HDR_FRAG_END) {
				rc->last_frag = true;
				tmp &= ~HDR_FRAG_END;
			}
			if (tmp > MAX_FRAG_SZ)
				goto err_out;

			rc->state = get_data;
			gnet_conn_readn(conn, tmp);
			gnet_conn_timeout(conn, TMOUT_READ);
			break;

		case get_data:
			/* avoiding alloc+copy, in a common case */
			if (rc->last_frag && !rc->msg) {
				rpc_msg(rc, evt->buffer, evt->length);
				break;
			}

			mem = realloc(rc->msg, rc->msg_len + evt->length);
			if (!mem) {
				syslog(LOG_ERR, "OOM in RPC get-data");
				goto err_out;
			}

			rc->msg = mem;
			memcpy(rc->msg + rc->msg_len, evt->buffer, evt->length);
			rc->msg_len += evt->length;

			if (rc->last_frag) {
				rpc_msg(rc, rc->msg, rc->msg_len);

				free(rc->msg);
				rc->msg = NULL;
				rc->msg_len = 0;
				rc->next_frag = 0;
				rc->last_frag = false;
			}

			rc->state = get_hdr;
			gnet_conn_readn(conn, 4);
			gnet_conn_timeout(conn, TMOUT_READ_HDR);
			break;
		}
		break;
	
	default:
		syslog(LOG_ERR, "unhandled GConnEvent %d", evt->type);
		break;
	}

	return;

err_out:
	rpc_cxn_free(rc);
}

static void server_event(GServer *gsrv, GConn *conn, gpointer user_data)
{
	struct nfs_server *server = user_data;
	struct rpc_cxn *rc;

	if (!conn) {
		syslog(LOG_ERR, "GServer exiting");
		return;
	}

	rc = calloc(1, sizeof(*rc));
	if (!rc) {
		gnet_conn_unref(conn);
		syslog(LOG_ERR, "OOM in server_event");
		return;
	}

	rc->server = server;
	rc->conn = conn;
	rc->state = get_hdr;

	gnet_conn_set_callback(conn, rpc_cxn_event, rc);

	gnet_conn_readn(conn, 4);
	gnet_conn_timeout(conn, TMOUT_READ_HDR);
}

static GMainLoop *init_server(void)
{
	struct timezone tz = { 0, 0 };
	GMainLoop *loop;

	loop = g_main_loop_new(NULL, FALSE);

	memset(&srv, 0, sizeof(srv));
	INIT_LIST_HEAD(&srv.dead_state);
	srv.lease_time = 5 * 60;
	srv.client_ids = g_hash_table_new_full(clientid_hash, clientid_equal,
					       NULL, NULL);
	srv.clid_idx = g_hash_table_new_full(g_direct_hash, g_direct_equal,
					     NULL, NULL);
	srv.state = g_hash_table_new_full(g_direct_hash, g_direct_equal,
					  NULL, state_free);

	if (gettimeofday(&current_time, &tz) < 0) {
		slerror("gettimeofday(2)");
		return NULL;
	}

	if (!srv.client_ids || !srv.clid_idx || !srv.state) {
		syslog(LOG_ERR, "OOM in init_server()");
		return NULL;
	}

	inode_table_init();

	init_rng();
	rand_verifier(&srv.instance_verf);

	tcpsrv = gnet_server_new(NULL, opt_nfs_port, server_event, &srv);
	if (!tcpsrv)
		return NULL;

	return loop;
}

static error_t parse_opt (int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'd':
		debugging = 1;
		break;
	case 'f':
		opt_foreground = true;
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
	GMainLoop *loop;
	error_t rc;

	setlocale(LC_ALL, "");

	gnet_init();

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

	loop = init_server();
	if (!loop)
		return 1;

	syslog(LOG_INFO, PACKAGE_STRING " initialized%s",
	       debugging ? " (DEBUG MODE)" : "");

	g_main_loop_run(loop);

	syslog(LOG_INFO, "server exit");
	return 0;
}

