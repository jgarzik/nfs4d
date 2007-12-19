
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
#include <openssl/sha.h>
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
static char *pid_fn = "nfs4_ramd.pid";
static bool pid_opened;
static unsigned int opt_nfs_port = 2049;
static GServer *tcpsrv;
static GHashTable *request_cache;

static LIST_HEAD(timer_list);
static unsigned int timer_source;
static uint64_t timer_expire;

static const char doc[] =
"nfs4-ram - NFS4 server daemon";

enum rpc_cxn_state {
	get_hdr,
	get_data
};

struct rpc_cxn {
	struct nfs_server	*server;

	GConn			*conn;
	char			*host;

	enum rpc_cxn_state	state;

	void			*msg;
	unsigned int		msg_len;
	unsigned int		next_frag;
	bool			last_frag;
};

struct drc_ent {
	unsigned char		md[SHA_DIGEST_LENGTH];

	struct nfs_timer	timer;

	void			*val;
	unsigned int		len;
};

static struct argp_option options[] = {
	{ "debug", 'd', "LEVEL", 0,
	  "Enable debug output (0 = no debug, increase for more verbosity)" },
	{ "foreground", 'f', NULL, 0,
	  "Run daemon in foreground" },
	{ "port", 'p', "PORT", 0,
	  "Bind to TCP port PORT (def. 2049)" },
	{ "pid", 'P', "FILE", 0,
	  "Write daemon process id to FILE" },

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
		memcpy(&sid->server_verf, verf, sizeof(verifier4));
}

static unsigned int wr_free(struct rpc_write *wr)
{
	return wr->alloc_len - wr->len;
}

static struct rpc_write *wr_alloc(unsigned int n)
{
	struct rpc_write *wr = calloc(1, sizeof(*wr));
	if (!wr) {
		syslog(LOG_ERR, "OOM in wr_skip()");
		return NULL;
	}

	if (n < RPC_WRITE_BUFSZ)
		n = RPC_WRITE_BUFSZ;

	wr->buf = malloc(n);
	if (!wr->buf) {
		free(wr);
		syslog(LOG_ERR, "OOM(2) in wr_skip()");
		return NULL;
	}

	wr->alloc_len = n;
	INIT_LIST_HEAD(&wr->node);

	return wr;
}

void *wr_skip(struct list_head *writes, struct rpc_write **wr_io,
		     unsigned int n)
{
	struct rpc_write *wr = *wr_io;
	void *buf;

	if (n > wr_free(wr)) {
		wr = wr_alloc(n);
		if (!wr)
			return NULL;

		list_add_tail(&wr->node, writes);
		*wr_io = wr;
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

static guint sha_hash_hash(gconstpointer key)
{
	const unsigned char *md = key;
	guint res;

	memcpy(&res, md, sizeof(res));
	return res;
}

static gboolean sha_hash_equal(gconstpointer a, gconstpointer b)
{
	return memcmp(a, b, SHA_DIGEST_LENGTH) == 0 ? TRUE : FALSE;
}

static void drc_timer(struct nfs_timer *timer, void *priv)
{
	struct drc_ent *drc = priv;

	g_hash_table_remove(request_cache, drc->md);

	memset(drc, 0, sizeof(*drc));
	free(drc);

	if (debugging > 1)
		syslog(LOG_DEBUG, "DRC cache expire");
}

static struct drc_ent *drc_lookup(const unsigned char *md)
{
	return g_hash_table_lookup(request_cache, md);
}

static void drc_store(const unsigned char *md, void *cache,
		      unsigned int cache_len)
{
	struct drc_ent *drc;

	if (!cache || !cache_len)
		return;

	drc = malloc(sizeof(*drc));
	if (!drc)
		return;		/* ok to ignore OOM here */

	memcpy(drc->md, md, SHA_DIGEST_LENGTH);
	timer_init(&drc->timer, drc_timer, drc);
	drc->val = cache;
	drc->len = cache_len;

	g_hash_table_insert(request_cache, drc->md, drc);

	timer_renew(&drc->timer, SRV_DRC_TIME);
}

void timer_del(struct nfs_timer *timer)
{
	if (timer->queued) {
		list_del_init(&timer->node);
		timer->queued = false;
	}
}

static void timer_requeue(struct nfs_timer *timer)
{
	struct list_head *tmp;
	struct nfs_timer *tmp_timer;

	/* if this is merely an expiration time change, the
	 * timer may already be on timer_list.  if so, remove it
	 */
	timer_del(timer);

	timer->queued = true;

	/* if list empty, addition is easy */
	if (list_empty(&timer_list)) {
		list_add(&timer->node, &timer_list);
		return;
	}

	/* insert into timer_list in order, iterating from tail to head,
	 * sorted by expire time
	 */
	tmp = timer_list.prev;		/* grab list tail */
	while (tmp != &timer_list) {
		tmp_timer = list_entry(tmp, struct nfs_timer, node);

		if (timer->expire >= tmp_timer->expire)
			break;

		tmp = tmp->prev;
	}

	/* if search failed, we have the lowest expire time, and
	 * belong at the head of the list
	 */
	if (tmp == &timer_list)
		list_add(&timer->node, &timer_list);

	/* otherwise, insert in the middle of the list */
	else {
		struct list_head *before, *me, *after;

		before	= &tmp_timer->node;
		me	= &timer->node;
		after	= before->next;

		me->prev = before;
		me->next = after;

		before->next = me;
		after->prev = me;
	}
}

static gboolean timer_cb(gpointer dummy)
{
	struct timezone tz = { 0, 0 };
	struct nfs_timer *timer;
	uint64_t next_expire = 0xffffffffffffffffULL;

	if (debugging > 1)
		syslog(LOG_INFO, "TIMER callback");

	gettimeofday(&current_time, &tz);

	/*
	 * iterate through timer_list, which is sorted by absolute
	 * expire time.  when we reach an expire time in the future,
	 * cease iteration.  we must delete the timer before calling
	 * the callback, in case the callback decides to requeue the
	 * timer.
	 */
	while (!list_empty(&timer_list)) {
		timer = list_entry(timer_list.next, struct nfs_timer, node);

		if (current_time.tv_sec < timer->expire) {
			if (timer->expire < next_expire)
				next_expire = timer->expire;
			break;
		}

		timer_del(timer);

		timer->cb(timer, timer->private);
	}

	if (list_empty(&timer_list)) {
		timer_source = 0;
		timer_expire = 0;
	} else {
		uint64_t interval = (next_expire - current_time.tv_sec) * 1000;
		timer_source = g_timeout_add(interval, timer_cb, NULL);
	}

	return FALSE;
}

void timer_renew(struct nfs_timer *timer, unsigned int seconds)
{
	uint64_t interval = 0;

	if (debugging > 1)
		syslog(LOG_INFO, "TIMER renew (%u secs)", seconds);

	timer->expire = current_time.tv_sec + seconds;
	if (!timer_expire || (timer->expire < timer_expire))
		timer_expire = timer->expire;

	timer_requeue(timer);

	if (timer_expire > current_time.tv_sec)
		interval = timer_expire - current_time.tv_sec;

	/* FIXME: if we reduce timer_expire, we should update
	 * the existing timer
	 */

	if (!timer_source)
		timer_source = g_timeout_add(interval * 1000, timer_cb, NULL);
}

void timer_init(struct nfs_timer *timer, nfs_timer_cb_t cb, void *priv)
{
	timer->cb = cb;
	timer->private = priv;
	timer->expire = 0;
	INIT_LIST_HEAD(&timer->node);
	timer->queued = false;
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
	uint32_t n_writes = 0, n_wbytes = 0;
	uint32_t *record_size, tmp_tot = 0;
	SHA_CTX ctx;
	unsigned int cache_len = 0, cache_used = 0;
	unsigned char md[SHA_DIGEST_LENGTH];
	struct drc_ent *drc;
	char *cache = NULL;
	int drc_mask = 0;

	_wr = NULL;
	wr = &_wr;
	writes = &_writes;
	INIT_LIST_HEAD(writes);

	gettimeofday(&current_time, &tz);

	SHA1_Init(&ctx);
	SHA1_Update(&ctx, rc->host, strlen(rc->host));
	SHA1_Update(&ctx, msg, msg_len > 256 ? 256 : msg_len);
	SHA1_Final(md, &ctx);

	drc = drc_lookup(md);
	if (drc) {
		timer_renew(&drc->timer, SRV_DRC_TIME);
		gnet_conn_write(rc->conn, drc->val, drc->len);
		if (debugging > 1)
			syslog(LOG_DEBUG, "RPC DRC cache hit (%u bytes)",
			       drc->len);
		return;
	}

	/*
	 * decode RPC header
	 */

	xid = CR32();			/* xid */
	if (CR32() != CALL) {		/* msg type */
		if (debugging > 1)
			syslog(LOG_DEBUG, "RPC: invalid msg type");
		goto err_out;
	}
	if ((CR32() != 2) ||		/* rpc version */
	    (CR32() != NFS4_PROGRAM) ||	/* rpc program */
	    (CR32() != NFS_V4))	{	/* rpc program version */
		if (debugging > 1)
			syslog(LOG_DEBUG, "RPC: invalid msg hdr");
		goto err_out;
	}
	proc = CR32();

	auth_cred.oa_flavor = CR32();
	auth_cred.oa_length = CR32();
	auth_cred.oa_base = CURMEM(auth_cred.oa_length);
	auth_verf.oa_flavor = CR32();
	auth_verf.oa_length = CR32();
	auth_verf.oa_base = CURMEM(auth_verf.oa_length);

	/*
	 * begin the RPC response message
	 */
	_wr = wr_alloc(0);
	if (!_wr) {
		syslog(LOG_ERR, "RPC: out of memory");
		goto err_out;
	}

	list_add_tail(&_wr->node, writes);

	record_size = WRSKIP(4);
	WR32(xid);			/* xid */
	WR32(REPLY);			/* message type */
	WR32(MSG_ACCEPTED);		/* reply status */

	WR32(AUTH_NULL);		/* opaque auth flavor, contents */
	WR32(0);

	WR32(0);			/* accept status (0 == success) */

	if (debugging > 1)
		syslog(LOG_DEBUG, "RPC: message (%u bytes, xid %x, proc %u)",
		       msg_len, xid, proc);

	/*
	 * handle RPC call
	 */

	switch (proc) {
	case NFSPROC4_NULL:
		drc_mask = nfsproc_null(rc->host, &auth_cred, &auth_verf, cur,
					writes, wr);
		break;
	case NFSPROC4_COMPOUND:
		drc_mask = nfsproc_compound(rc->host, &auth_cred, &auth_verf,
					    cur, writes, wr);
		break;
	default:
		goto err_out;
	}

	/*
	 * send response back to client asynchronously
	 * TODO: way too much alloc+copy
	 */

	tmp_tot = 0;
	list_for_each_entry(_wr, writes, node) {
		tmp_tot += _wr->len;
	}

	*record_size = htonl((tmp_tot - 4) | HDR_FRAG_END);

	if (drc_mask) {
		cache_len = tmp_tot;
		cache = malloc(cache_len);
	}

	list_for_each_entry_safe(_wr, iter, writes, node) {
		if (_wr->len) {
			gnet_conn_write(rc->conn, _wr->buf, _wr->len);

			if (cache) {
				memcpy(cache + cache_used, _wr->buf,
				       _wr->len);
				cache_used += _wr->len;
			}

			n_wbytes += _wr->len;
			n_writes++;
		}

		list_del(&_wr->node);
		free(_wr->buf);
		free(_wr);
	}

	drc_store(md, cache, cache_len);

	if (debugging > 1)
		syslog(LOG_DEBUG, "RPC reply: %u bytes, %u writes",
			n_wbytes, n_writes);

	return;

err_out:
	if (debugging > 1)
		syslog(LOG_DEBUG, "RPC: invalid message (%u bytes, xid %x), "
		       "ignoring",
		       msg_len, xid);
	/* FIXME: reply to bad XDR/RPC */
}

static void rpc_cxn_free(struct rpc_cxn *cxn)
{
	gnet_conn_unref(cxn->conn);
	free(cxn->msg);
	g_free(cxn->host);

	memset(cxn, 0, sizeof(*cxn));
	free(cxn);
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

	case GNET_CONN_WRITE:
		/* do nothing */
		if (debugging > 1)
			syslog(LOG_DEBUG, "async write complete");
		break;

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

			if (debugging > 1)
				syslog(LOG_DEBUG, "RPC frag (%u bytes%s)",
				       tmp,
				       rc->last_frag ? ", LAST" : "");

			rc->state = get_data;
			gnet_conn_readn(conn, tmp);
			gnet_conn_timeout(conn, TMOUT_READ);
			break;

		case get_data:
			/* avoiding alloc+copy, in a common case */
			if (rc->last_frag && !rc->msg) {
				rpc_msg(rc, evt->buffer, evt->length);
				rc->msg_len = 0;
				rc->next_frag = 0;
				rc->last_frag = false;
			} else {
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
	char *host;

	if (!conn) {
		syslog(LOG_ERR, "GServer exiting");
		return;
	}

	host = gnet_inetaddr_get_canonical_name(conn->inetaddr);
	syslog(LOG_INFO, "TCP connection from %s",
	       host ? host : "<oom?>");

	rc = calloc(1, sizeof(*rc));
	if (!rc) {
		gnet_conn_unref(conn);
		syslog(LOG_ERR, "OOM in server_event");
		return;
	}

	rc->server = server;
	rc->conn = conn;
	rc->state = get_hdr;
	rc->host = host;

	gnet_conn_set_callback(conn, rpc_cxn_event, rc);

	gnet_conn_readn(conn, 4);
	gnet_conn_timeout(conn, TMOUT_READ_HDR);
}

void syslogerr(const char *prefix)
{
	syslog(LOG_ERR, "%s: %s", prefix, strerror(errno));
}

static void write_pid_file(void)
{
	char str[32], *s;
	size_t bytes;

	sprintf(str, "%u\n", getpid());
	s = str;
	bytes = strlen(s);

	int fd = open(pid_fn, O_WRONLY | O_CREAT | O_EXCL, 0666);
	if (fd < 0) {
		syslogerr("open pid");
		exit(1);
	}

	while (bytes > 0) {
		ssize_t rc = write(fd, s, bytes);
		if (rc < 0) {
			syslogerr("write pid");
			exit(1);
		}

		bytes -= rc;
		s += rc;
	}

	if (close(fd) < 0) {
		syslogerr("close pid");
		exit(1);
	}

	pid_opened = true;
}

extern int id_init(void);

static GMainLoop *init_server(void)
{
	struct timezone tz = { 0, 0 };
	GMainLoop *loop;

	write_pid_file();

	loop = g_main_loop_new(NULL, FALSE);

	memset(&srv, 0, sizeof(srv));
	srv.space_used = 1024 * 1024;
	srv.lease_time = SRV_LEASE_TIME;
	srv.clid_idx = g_hash_table_new_full(g_direct_hash, g_direct_equal,
					     NULL, NULL);
	srv.state = g_hash_table_new_full(g_direct_hash, g_direct_equal,
					  NULL, state_free);
	request_cache = g_hash_table_new(sha_hash_hash, sha_hash_equal);

	if (gettimeofday(&current_time, &tz) < 0) {
		slerror("gettimeofday(2)");
		return NULL;
	}

	if (!srv.clid_idx || !srv.state || !request_cache) {
		syslog(LOG_ERR, "OOM in init_server()");
		return NULL;
	}

	if (id_init()) {
		syslog(LOG_ERR, "identity map initialization failed");
		return NULL;
	}

	inode_table_init();

	init_rng();
	rand_verifier(&srv.instance_verf);

	tcpsrv = gnet_server_new(NULL, opt_nfs_port, server_event, &srv);
	if (!tcpsrv) {
		syslog(LOG_ERR, "GServer init failed");
		return NULL;
	}

	return loop;
}

static error_t parse_opt (int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'd':
		if (atoi(arg) >= 0 && atoi(arg) <= 2)
			debugging = atoi(arg);
		else {
			fprintf(stderr, "invalid debug level %s (valid: 0-2)\n",
				arg);
			argp_usage(state);
		}
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

	case 'P':
		pid_fn = arg;
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

static void srv_exit_cleanup(void)
{
	if (pid_opened && unlink(pid_fn) < 0)
		syslogerr("unlink");
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

	atexit(srv_exit_cleanup);
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

