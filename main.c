
/*
 * Copyright 2008-2009 Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING.  If not, write to
 * the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#define _GNU_SOURCE
#include "nfs4d-config.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <signal.h>
#include <argp.h>
#include <mcheck.h>
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
static char *opt_lcldom = "localdomain";
struct nfs_server srv;
struct refbuf pad_rb = { "\0\0\0\0", 4, 1 };

static char startup_cwd[PATH_MAX];
char my_hostname[HOST_NAME_MAX + 1];
static bool opt_foreground;
static char *pid_fn = "nfs4d.pid";
static char *stats_fn = "nfs4d.stats";
static char *dump_fn = "nfs4d.dump";
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
	char			host_addr[GNET_INETADDR_MAX_LEN];

	enum rpc_cxn_state	state;

	void			*msg;
	unsigned int		msg_len;
	unsigned int		next_frag;
	bool			last_frag;
};

struct drc_ent {
	unsigned long		hash;

	uint32_t		xid;
	char			host_addr[GNET_INETADDR_MAX_LEN];

	uint64_t		expire;

	void			*val;
	unsigned int		len;
};

static struct argp_option options[] = {
	{ "debug", 'd', "LEVEL", 0,
	  "Enable debug output (def. 0 = no debug, increase for more verbosity.  maximum: 2)" },
	{ "foreground", 'f', NULL, 0,
	  "Run daemon in foreground (def: chdir to /, detach, run in background)" },
	{ "port", 'p', "PORT", 0,
	  "Bind to TCP port PORT (def: 2049)" },
	{ "pid", 'P', "FILE", 0,
	  "Write daemon process id to FILE (def: nfs4d.pid, in current directory)" },
	{ "localdomain", 'O', "DOMAIN", 0,
	  "Local domain" },
	{ "stats", 'S', "FILE", 0,
	  "Statistics dumped to FILE, for each SIGUSR1 (def: nfs4d.stats, in current directory)" },
	{ "dump", 'D', "FILE", 0,
	  "Diagnostic RAM data dumped to FILE, for each SIGUSR2 (def: nfs4d.dump, in current directory)" },

	{ }
};

static error_t parse_opt (int key, char *arg, struct argp_state *state);
static const struct argp argp = { options, parse_opt, NULL, doc };

static void slerror(const char *prefix)
{
	syslog(LOG_ERR, "%s: %s", prefix, strerror(errno));
}

/* "djb2"-derived hash function */
static unsigned long blob_hash(unsigned long hash, const void *_buf,
			       size_t buflen)
{
	const unsigned char *buf = _buf;
	int c;

	while (buflen > 0) {
		c = *buf++;
		buflen--;

		hash = ((hash << 5) + hash) ^ c; /* hash * 33 ^ c */
	}

	return hash;
}

/* seed our RNGs with high quality data from /dev/random */
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
	srand(v);
	return;

srand_time:
	srand48_r(getpid() ^ time(NULL), &srv.rng);
	srand(getpid() ^ time(NULL));
}

struct refbuf *refbuf_new(unsigned int size, bool clear)
{
	struct refbuf *rb;

	rb = malloc(sizeof(*rb));
	if (!rb)
		return NULL;

	if (clear)
		rb->buf = calloc(1, size);
	else
		rb->buf = malloc(size);
	if (!rb->buf) {
		free(rb);
		return NULL;
	}

	rb->len = size;
	rb->refcnt = 1;

	return rb;
}

void refbuf_unref(struct refbuf *rb)
{
	if (G_UNLIKELY(!rb || !rb->len || !rb->refcnt)) {
		syslog(LOG_ERR, "BUG: invalid refbuf");
		return;
	}

	rb->refcnt--;

	if (rb->refcnt == 0) {
		free(rb->buf);
		free(rb);
	}
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
	return wr->rbuf->len - wr->len;
}

void wr_unref(struct rpc_write *wr)
{
	if (!wr)
		return;

	refbuf_unref(wr->rbuf);

	memset(wr, 0, sizeof(*wr));
	free(wr);
}

struct rpc_write *wr_ref(struct refbuf *rb, unsigned int ofs,
			 unsigned int len)
{
	struct rpc_write *wr = malloc(sizeof(*wr));
	if (G_UNLIKELY(!wr)) {
		syslog(LOG_ERR, "OOM in wr_ref()");
		return NULL;
	}

	if (G_UNLIKELY(len > (rb->len - ofs))) {
		syslog(LOG_ERR, "BUG in wr_ref()");
		return NULL;
	}

	wr->rbuf = refbuf_ref(rb);
	wr->buf = wr->rbuf->buf + ofs;
	wr->len = len;
	INIT_LIST_HEAD(&wr->node);

	return wr;
}

struct rpc_write *wr_alloc(unsigned int n)
{
	struct rpc_write *wr = malloc(sizeof(*wr));
	if (G_UNLIKELY(!wr)) {
		syslog(LOG_ERR, "OOM in wr_skip()");
		return NULL;
	}

	if (n < RPC_WRITE_BUFSZ)
		n = RPC_WRITE_BUFSZ;

	wr->rbuf = refbuf_new(n, false);
	if (G_UNLIKELY(!wr->rbuf)) {
		free(wr);
		syslog(LOG_ERR, "OOM(2) in wr_skip()");
		return NULL;
	}

	wr->buf = wr->rbuf->buf;
	wr->len = 0;
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

static void drc_ent_free(gpointer data)
{
	struct drc_ent *drc = data;

	if (!drc)
		return;

	free(drc->val);

	memset(drc, 0, sizeof(*drc));
	free(drc);

	srv.stats.drc_free++;
}

static void drc_gc_iter(gpointer key, gpointer val, gpointer user_data)
{
	struct drc_ent *ent = val;
	GList **list = user_data;

	if (current_time.tv_sec < ent->expire)
		return;

	*list = g_list_prepend(*list, ent);
}

static void drc_gc(void)
{
	GList *list = NULL, *tmp;
	struct drc_ent *drc;

	g_hash_table_foreach(request_cache, drc_gc_iter, &list);

	tmp = list;
	while (tmp) {
		drc = tmp->data;

		g_hash_table_remove(request_cache, (void *) drc->hash);

		tmp = tmp->next;
	}

	g_list_free(list);
}

static struct drc_ent *drc_lookup(unsigned long hash, uint32_t xid,
				  const char *host_addr)
{
	struct drc_ent *ent = g_hash_table_lookup(request_cache, (void *) hash);
	if (!ent)
		return NULL;

	if ((ent->xid != xid) ||
	    memcmp(ent->host_addr, host_addr, GNET_INETADDR_MAX_LEN))
		return NULL;

	return ent;
}

static void drc_store(unsigned long hash, void *cache, unsigned int cache_len,
		      uint32_t xid, const char *host_addr)
{
	struct drc_ent *drc;

	srv.stats.drc_store++;
	srv.stats.drc_store_bytes += cache_len;

	drc = malloc(sizeof(*drc));
	if (!drc) {
		free(cache);
		return;		/* ok to ignore OOM here */
	}

	drc->hash = hash;
	drc->expire = current_time.tv_sec + SRV_DRC_TIME;
	drc->val = cache;
	drc->len = cache_len;
	drc->xid = xid;
	memcpy(drc->host_addr, host_addr, GNET_INETADDR_MAX_LEN);

	g_hash_table_replace(request_cache, (void *) hash, drc);
}

void timer_del(struct nfs_timer *timer)
{
	if (timer->queued) {
		list_del_init(&timer->node);
		timer->queued = false;
	}
}

static gboolean timer_cb(gpointer dummy)
{
	struct timezone tz = { 0, 0 };
	struct nfs_timer *timer, *iter;
	uint64_t next_expire = 0;

	if (debugging > 1)
		syslog(LOG_INFO, "TIMER callback");

	gettimeofday(&current_time, &tz);

	list_for_each_entry_safe(timer, iter, &timer_list, node) {
		if (!next_expire)
			next_expire = timer->expire;
		else if (timer->expire < next_expire)
			next_expire = timer->expire;

		if (timer->expire > current_time.tv_sec)
			continue;

		timer_del(timer);

		timer->cb(timer, timer->private);
	}

	if (list_empty(&timer_list)) {
		timer_source = 0;
		timer_expire = 0;
	} else {
		unsigned int interval;

		if (next_expire > current_time.tv_sec) {
			interval = (next_expire - current_time.tv_sec) * 1000;
			timer_expire = next_expire;
		} else {
			interval = 1;
			timer_expire = current_time.tv_sec + 1;
		}

		timer_source = g_timeout_add(interval, timer_cb, NULL);
	}

	return FALSE;
}

void timer_renew(struct nfs_timer *timer, unsigned int seconds)
{
	uint64_t interval = 1;

	if (debugging > 1)
		syslog(LOG_INFO, "TIMER renew (%u secs)", seconds);

	timer->expire = current_time.tv_sec + seconds;
	if (!timer_expire || (timer->expire < timer_expire))
		timer_expire = timer->expire;

	if (!timer->queued) {
		timer->queued = true;
		list_add_tail(&timer->node, &timer_list);
	}

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

static void space_used_iter(struct nfs_inode *ino, uint64_t *total)
{
	*total += sizeof(struct nfs_inode);
	if (ino->mimetype)
		*total += strlen(ino->mimetype);

	switch (ino->type) {
	case NF4LNK:
		if (ino->linktext)
			*total += strlen(ino->linktext);
		break;

	case NF4DIR:
		/* wild approximation of dir space.
		 * iteration probably too costly.
		 */
		*total += 100;
		break;

	case NF4REG:
		*total += ino->size;
		break;

	default:
		/* do nothing */
		break;
	}
}

uint64_t srv_space_used(void)
{
	static uint64_t cached_total;
	static uint64_t ttl;
	uint64_t total = 0;
	unsigned int i;
	struct nfs_inode *ino;

	if (ttl && cached_total && (current_time.tv_sec < ttl))
		return cached_total;

	for (i = 0; i < srv.inode_table_len; i++) {
		ino = srv.inode_table[i];
		if (!ino || !ino->parents)
			continue;

		space_used_iter(ino, &total);
	}

	cached_total = total;
	ttl = current_time.tv_sec + SRV_SPACE_USED_TTL;

	return total;
}

static gboolean garbage_collect(gpointer dummy)
{
	if (debugging)
		syslog(LOG_DEBUG, "Garbage collection");

	drc_gc();
	state_gc();

	return FALSE;
}

static void rpc_msg(struct rpc_cxn *rc, void *msg, unsigned int msg_len)
{
	static uint64_t garbage_time;

	struct timezone tz = { 0, 0 };
	struct curbuf _cur = { msg, msg, msg_len, msg_len };
	struct curbuf *cur = &_cur;
	uint32_t proc, xid;
	struct opaque_auth auth_cred, auth_verf;
	struct rpc_write *_wr, *iter, **wr;
	struct list_head _writes, *writes;
	uint32_t n_writes = 0, n_wbytes = 0;
	uint32_t *record_size, tmp_tot = 0;
	unsigned int cache_len = 0, cache_used = 0;
	unsigned long hash;
	struct drc_ent *drc;
	char *cache = NULL;
	int drc_mask = 0;

	srv.stats.rpc_msgs++;

	_wr = NULL;
	wr = &_wr;
	writes = &_writes;
	INIT_LIST_HEAD(writes);

	gettimeofday(&current_time, &tz);

	if (current_time.tv_sec > garbage_time) {
		garbage_time = current_time.tv_sec + SRV_GARBAGE_TIME;
		g_idle_add(garbage_collect, NULL);
	}

	hash = blob_hash(BLOB_HASH_INIT, msg, MIN(msg_len, 128));

	xid = CR32();			/* xid */

	drc = drc_lookup(hash, xid, rc->host_addr);
	if (drc) {
		srv.stats.drc_hits++;
		drc->expire = current_time.tv_sec + SRV_DRC_TIME;
		gnet_conn_write(rc->conn, drc->val, drc->len);
		if (debugging > 1)
			syslog(LOG_DEBUG, "RPC DRC cache hit (%u bytes)",
			       drc->len);
		return;
	} else
		srv.stats.drc_misses++;

	/*
	 * decode RPC header (except xid, which was input above)
	 */

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
		srv.stats.proc_null++;
		drc_mask = nfsproc_null(rc->host, &auth_cred, &auth_verf, cur,
					writes, wr);
		break;
	case NFSPROC4_COMPOUND:
		srv.stats.proc_compound++;
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
		wr_unref(_wr);
	}

	srv.stats.sock_tx_bytes += n_wbytes;

	if (cache)
		drc_store(hash, cache, cache_len, xid, rc->host_addr);

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
			srv.stats.sock_rx_bytes += 4;

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
			srv.stats.sock_rx_bytes += evt->length;

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
	if (!host)
		goto err_out;

	syslog(LOG_INFO, "TCP connection from %s", host);

	rc = calloc(1, sizeof(*rc));
	if (!rc)
		goto err_out;

	rc->server = server;
	rc->conn = conn;
	rc->state = get_hdr;
	rc->host = host;
	gnet_inetaddr_get_bytes(conn->inetaddr, rc->host_addr);

	gnet_conn_set_callback(conn, rpc_cxn_event, rc);

	gnet_conn_readn(conn, 4);
	gnet_conn_timeout(conn, TMOUT_READ_HDR);

	return;

err_out:
	gnet_conn_unref(conn);
	syslog(LOG_ERR, "OOM in server_event");
}

void syslogerr(const char *prefix)
{
	syslog(LOG_ERR, "%s: %s", prefix, strerror(errno));
}

static void write_pid_file(void)
{
	char str[32], *s;
	size_t bytes;

	if (pid_fn[0] != '/') {
		char *fn;

		if (asprintf(&fn, "%s%s", startup_cwd, pid_fn) < 0)
			exit(1);

		pid_fn = fn;		/* NOTE: never freed */
	}

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

static GMainLoop *init_server(void)
{
	struct timezone tz = { 0, 0 };
	GMainLoop *loop;

	write_pid_file();

	loop = g_main_loop_new(NULL, FALSE);

	memset(&srv, 0, sizeof(srv));
	INIT_LIST_HEAD(&srv.dead);
	srv.lease_time = SRV_LEASE_TIME;
	srv.clid_idx = g_hash_table_new_full(g_direct_hash, g_direct_equal,
					     NULL, NULL);
	srv.openfiles = g_hash_table_new_full(g_direct_hash, g_direct_equal,
					  NULL, openfile_free);
	request_cache = g_hash_table_new_full(g_direct_hash, g_direct_equal,
					 NULL, drc_ent_free);
	srv.localdom = opt_lcldom;

	if (gettimeofday(&current_time, &tz) < 0) {
		slerror("gettimeofday(2)");
		return NULL;
	}

	if (!srv.clid_idx || !srv.openfiles || !request_cache) {
		syslog(LOG_ERR, "OOM in init_server()");
		return NULL;
	}

	if (fsdb_open(&srv.fsdb, DB_RECOVER | DB_CREATE, DB_CREATE,
		     "nfs4d", true))
		return NULL;

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
	case 'O':
		opt_lcldom = arg;
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

	case 'D':
		dump_fn = arg;
		break;

	case 'S':
		stats_fn = arg;
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

static char stats_buf[4096 * 2];

static gboolean stats_dump(gpointer dummy)
{
	struct timezone tz = { 0, 0 };
	int fd;

	gettimeofday(&current_time, &tz);

	snprintf(stats_buf, sizeof(stats_buf),
		"========== %Lu.%Lu\n"
		"sock_rx_bytes: %Lu\n"
		"sock_tx_bytes: %Lu\n"
		"read_bytes: %Lu\n"
		"write_bytes: %Lu\n"
		"rpc_msgs: %lu\n"
		"op_access: %lu\n"
		"op_close: %lu\n"
		"op_commit: %lu\n"
		"op_create: %lu\n"
		"op_getattr: %lu\n"
		"op_getfh: %lu\n"
		"op_link: %lu\n"
		"op_lock: %lu\n"
		"op_testlock: %lu\n"
		"op_unlock: %lu\n"
		"op_lookup: %lu\n"
		"op_lookupp: %lu\n"
		"op_nverify: %lu\n"
		"op_open: %lu\n"
		"op_open_confirm: %lu\n"
		"op_open_downgrade: %lu\n"
		"op_putfh: %lu\n"
		"op_putpubfh: %lu\n"
		"op_putrootfh: %lu\n"
		"op_read: %lu\n"
		"op_readdir: %lu\n"
		"op_readlink: %lu\n"
		"op_release_lockowner: %lu\n"
		"op_remove: %lu\n"
		"op_rename: %lu\n"
		"op_renew: %lu\n"
		"op_restorefh: %lu\n"
		"op_savefh: %lu\n"
		"op_secinfo: %lu\n"
		"op_setattr: %lu\n"
		"op_setclientid: %lu\n"
		"op_setclientid_confirm: %lu\n"
		"op_verify: %lu\n"
		"op_write: %lu\n"
		"op_notsupp: %lu\n"
		"op_illegal: %lu\n"
		"proc_null: %lu\n"
		"proc_compound: %lu\n"
		"compound_ok: %lu\n"
		"compound_fail: %lu\n"
		"openfile_objs: %u\n"
		"openfile_alloc: %lu\n"
		"openfile_free: %lu\n"
		"clid_objs: %u\n"
		"clid_alloc: %lu\n"
		"clid_free: %lu\n"
		"drc_free: %lu\n"
		"drc_store: %lu\n"
		"drc_store_bytes: %Lu\n"
		"drc_hits: %lu\n"
		"drc_misses: %lu\n"
		"inode_objs: %u\n"
		"========== %Lu.%Lu\n",

		(unsigned long long) current_time.tv_sec,
		(unsigned long long) current_time.tv_usec,
		srv.stats.sock_rx_bytes,
		srv.stats.sock_tx_bytes,
		srv.stats.read_bytes,
		srv.stats.write_bytes,
		srv.stats.rpc_msgs,
		srv.stats.op_access,
		srv.stats.op_close,
		srv.stats.op_commit,
		srv.stats.op_create,
		srv.stats.op_getattr,
		srv.stats.op_getfh,
		srv.stats.op_link,
		srv.stats.op_lock,
		srv.stats.op_testlock,
		srv.stats.op_unlock,
		srv.stats.op_lookup,
		srv.stats.op_lookupp,
		srv.stats.op_nverify,
		srv.stats.op_open,
		srv.stats.op_open_confirm,
		srv.stats.op_open_downgrade,
		srv.stats.op_putfh,
		srv.stats.op_putpubfh,
		srv.stats.op_putrootfh,
		srv.stats.op_read,
		srv.stats.op_readdir,
		srv.stats.op_readlink,
		srv.stats.op_release_lockowner,
		srv.stats.op_remove,
		srv.stats.op_rename,
		srv.stats.op_renew,
		srv.stats.op_restorefh,
		srv.stats.op_savefh,
		srv.stats.op_secinfo,
		srv.stats.op_setattr,
		srv.stats.op_setclientid,
		srv.stats.op_setclientid_confirm,
		srv.stats.op_verify,
		srv.stats.op_write,
		srv.stats.op_notsupp,
		srv.stats.op_illegal,
		srv.stats.proc_null,
		srv.stats.proc_compound,
		srv.stats.compound_ok,
		srv.stats.compound_fail,
		g_hash_table_size(srv.openfiles),
		srv.stats.openfile_alloc,
		srv.stats.openfile_free,
		g_hash_table_size(srv.clid_idx),
		srv.stats.clid_alloc,
		srv.stats.clid_free,
		srv.stats.drc_free,
		srv.stats.drc_store,
		srv.stats.drc_store_bytes,
		srv.stats.drc_hits,
		srv.stats.drc_misses,
		srv.inode_table_len,
		(unsigned long long) current_time.tv_sec,
		(unsigned long long) current_time.tv_usec);

	if (stats_fn[0] != '/') {
		char *fn;

		if (asprintf(&fn, "%s%s", startup_cwd, stats_fn) < 0)
			exit(1);

		stats_fn = fn;		/* NOTE: never freed */
	}

	fd = open(stats_fn, O_WRONLY | O_APPEND | O_CREAT, 0644);
	if (fd < 0) {
		syslog(LOG_ERR, "open(%s): %s", stats_fn, strerror(errno));
		return FALSE;
	}

	if (write(fd, stats_buf, strlen(stats_buf)) < 0) {
		syslog(LOG_ERR, "write(%s, %lu): %s",
		       stats_fn,
		       (unsigned long) strlen(stats_buf),
		       strerror(errno));
		close(fd);
		return FALSE;
	}

	if (close(fd) < 0)
		syslog(LOG_ERR, "close(%s): %s", stats_fn, strerror(errno));

	return FALSE;
}

static void stats_signal(int signal)
{
	syslog(LOG_INFO, "Got SIGUSR1, initiating bg stat dump");

	g_idle_add(stats_dump, NULL);
}

static gboolean dump_dir_iter(gpointer _k, gpointer _v, gpointer _d)
{
	struct nfs_dirent *de = _v;
	FILE *f = _d;

	fprintf(f, "\tDIRENT (%llu) == %.*s\n",
		(unsigned long long) de->inum,
		de->name.len,
		de->name.val);

	return FALSE;
}

static void dump_inode(FILE *f, const struct nfs_inode *ino)
{
	unsigned int i;

	if (!ino)
		return;

	fprintf(f,
		"INODE: %llu\n"
		"type: %s\n"
		"version: %Lu\n"
		,
		(unsigned long long) ino->inum,
		name_nfs_ftype4[ino->type],
		(unsigned long long) ino->version);

	if (ino->ctime || ino->atime || ino->mtime)
		fprintf(f, "time: create %Lu access %Lu modify %Lu\n",
			(unsigned long long) ino->ctime,
			(unsigned long long) ino->atime,
			(unsigned long long) ino->mtime);
	if (ino->mode)
		fprintf(f, "mode: %o\n", ino->mode);
	if (ino->user)
		fprintf(f, "user: %s\n", ino->user);
	if (ino->group)
		fprintf(f, "group: %s\n", ino->group);
	if (ino->mimetype)
		fprintf(f, "mime-type: %s\n", ino->mimetype);

	if (ino->parents) {
		fprintf(f, "parent%s:",
			ino->parents->len > 1 ? "s" : "");

		for (i = 0; i < ino->parents->len; i++) {
			struct nfs_fh *fh;

			fh = &g_array_index(ino->parents, struct nfs_fh, i);
			fprintf(f, " %llu", (unsigned long long) fh->inum);
		}

		fprintf(f, "\n");
	}

	switch (ino->type) {
	case NF4DIR:
		fprintf(f, "dir-length: %u\n", g_tree_nnodes(ino->dir));
		g_tree_foreach(ino->dir, dump_dir_iter, f);
		break;
	case NF4LNK:
		fprintf(f, "linktext: %s\n", ino->linktext);
		break;
	case NF4BLK:
	case NF4CHR:
		fprintf(f, "devdata: %u %u\n", ino->devdata[0], ino->devdata[1]);
		break;
	case NF4REG:
		fprintf(f, "size: %Lu\n", (unsigned long long) ino->size);
		break;

	default:
		/* do nothing */
		break;
	}

	fprintf(f, "===========================\n");
}

static gboolean diag_dump(gpointer dummy)
{
	FILE *f;
	unsigned int i;

	if (dump_fn[0] != '/') {
		char *fn;

		if (asprintf(&fn, "%s%s", startup_cwd, dump_fn) < 0)
			exit(1);

		dump_fn = fn;		/* NOTE: never freed */
	}

	f = fopen(dump_fn, "a");
	if (!f) {
		syslogerr(dump_fn);
		goto out;
	}

	fprintf(f, "inode-table-size: %u\n", srv.inode_table_len);

	for (i = 0; i < srv.inode_table_len; i++)
		dump_inode(f, srv.inode_table[i]);

out:
	return FALSE;
}

static void dump_signal(int signal)
{
	syslog(LOG_INFO, "Got SIGUSR2, initiating bg diag dump");

	g_idle_add(diag_dump, NULL);
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

	mcheck(NULL);

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
	signal(SIGUSR1, stats_signal);
	signal(SIGUSR2, dump_signal);

	openlog("nfs4d", LOG_PID, LOG_LOCAL2);

	if (getcwd(startup_cwd, sizeof(startup_cwd) - 2) < 0) {
		syslogerr("getcwd(2)");
		return 1;
	}
	if (startup_cwd[strlen(startup_cwd) - 1] != '/')
		strcat(startup_cwd, "/");

	/* get our hostname, for fs_locations' use */
	if (gethostname(my_hostname, sizeof(my_hostname) - 1) < 0) {
		syslogerr("gethostname(2)");
		return 1;
	}
	my_hostname[sizeof(my_hostname) - 1] = 0;

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

	fsdb_close(&srv.fsdb);

	syslog(LOG_INFO, "server exit");
	return 0;
}

