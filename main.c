
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
#include <sys/socket.h>
#include <sys/uio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <stdio.h>
#include <signal.h>
#include <argp.h>
#include <locale.h>
#include <netdb.h>
#include <syslog.h>
#include <event.h>
#include "server.h"

struct rpc_cxn;
struct rpc_cxn_write;

enum {
	LISTEN_SIZE		= 100,

	TMOUT_READ_HDR		= 30 * 60 * 1000,	/* 30 min (units: ms) */
	TMOUT_READ		= 60 * 60 * 1000,	/* 60 min (units: ms) */

	MAX_FRAG_SZ		= 50 * 1024 * 1024,	/* arbitrary */
	MAX_MSG_SZ		= MAX_FRAG_SZ,

	HDR_FRAG_END		= (1U << 31),

	CLI_MAX_WR_IOV		= 32,		/* max iov per writev(2) */

	HOST_ADDR_MAX_LEN	= 256,
};

int debugging = 0;
static char *opt_lcldom = "localdomain";
struct nfs_server srv;
struct refbuf pad_rb = { "\0\0\0\0", 4, 1 };

static char startup_cwd[PATH_MAX];
char my_hostname[HOST_NAME_MAX + 1];
static bool server_running = true;
static bool dump_stats = false;
static bool opt_foreground;
static bool opt_txn_nosync;
static char *opt_data_path = "/tmp/data/";
static char *opt_metadata = "/tmp/metadata/";
static char *pid_fn = "nfs4d.pid";
static char *stats_fn = "nfs4d.stats";
static bool pid_opened;
static unsigned int opt_nfs_port = 2049;
static GHashTable *request_cache;
static struct event garbage_timer;

static const char doc[] =
"nfs4-ram - NFS4 server daemon";

typedef bool (*cxn_evt_func)(struct rpc_cxn *, short);
typedef bool (*cxn_write_func)(struct rpc_cxn *, struct rpc_cxn_write *, bool);

/* internal client socket state */
enum rpc_cxn_state {
	evt_get_hdr,
	evt_get_data,
	evt_rpc_msg,
	evt_dispose,				/* dispose of client */
};

struct server_socket {
	int			fd;
	struct event		ev;
};

struct rpc_cxn_write {
	const void		*buf;		/* write buffer */
	int			len;		/* write buffer length */
	cxn_write_func		cb;		/* callback */
	void			*cb_data;	/* data passed to cb */

	struct list_head	node;
};

struct rpc_cxn {
	int			fd;

	struct sockaddr_in6	addr;

	struct event		ev;
	struct event		write_ev;

	char			*host;
	char			host_addr[HOST_ADDR_MAX_LEN];

	enum rpc_cxn_state	state;

	void			*msg;
	unsigned int		msg_len;
	unsigned int		next_frag;
	bool			last_frag;

	char			hdr[4];
	unsigned int		hdr_used;

	struct list_head	write_q;	/* list of async writes */
	bool			writing;
};

struct drc_ent {
	unsigned long		hash;

	uint32_t		xid;
	char			host_addr[HOST_ADDR_MAX_LEN];

	uint64_t		expire;

	void			*val;
	unsigned int		len;
};


static int cxn_writeq(struct rpc_cxn *cxn, const void *buf, unsigned int buflen,
		      cxn_write_func cb, void *cb_data);
static bool cxn_write_start(struct rpc_cxn *cxn);
static void tcp_cxn_event(int fd, short events, void *userdata);
static void stats_dump(void);


static struct argp_option options[] = {
	{ "metadata", 'M', "DIRECTORY", 0,
	  "Metadata directory" },
	{ "data", 'D', "DIRECTORY", 0,
	  "Data directory" },

	{ "port", 'p', "PORT", 0,
	  "Bind to TCP port PORT (def: 2049)" },
	{ "pid", 'P', "FILE", 0,
	  "Write daemon process id to FILE (def: nfs4d.pid, in current dir)" },

	{ "debug", 'd', "LEVEL", 0,
	  "Enable debug output (def. 0 = no debug, 2 = maximum debug output)" },

	{ "foreground", 'f', NULL, 0,
	  "Run daemon in foreground (def: chdir to /, detach, run in background)" },

	{ "localdomain", 'O', "DOMAIN", 0,
	  "Local domain (def: gethostname; used with user/group ids, required by NFS)" },

	{ "stats", 'S', "FILE", 0,
	  "Statistics dumped to FILE, for each SIGUSR1 (def: nfs4d.stats, in current directory)" },

	{ "no-sync", 'N', NULL, 0,
	  "Disable synchronous log flushing.  Increases performance, decreases durability" },

	{ }
};

static error_t parse_opt (int key, char *arg, struct argp_state *state);
static const struct argp argp = { options, parse_opt, NULL, doc };

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

static struct refbuf *refbuf_new(unsigned int size, bool clear)
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

static void refbuf_unref(struct refbuf *rb)
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

static unsigned int wr_free_space(struct rpc_write *wr)
{
	return wr->rbuf->len - wr->len;
}

void wr_free(struct rpc_write *wr)
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
		syslog(LOG_ERR, "OOM in wr_alloc()");
		return NULL;
	}

	if (n < RPC_WRITE_BUFSZ)
		n = RPC_WRITE_BUFSZ;

	wr->rbuf = refbuf_new(n, false);
	if (G_UNLIKELY(!wr->rbuf)) {
		free(wr);
		syslog(LOG_ERR, "OOM(2) in wr_alloc()");
		return NULL;
	}

	wr->buf = wr->rbuf->buf;
	wr->len = 0;
	INIT_LIST_HEAD(&wr->node);

	return wr;
}

static bool wr_done_cb(struct rpc_cxn *cxn, struct rpc_cxn_write *rpcwr,
		       bool done)
{
	struct rpc_write *wr = rpcwr->cb_data;

	wr_free(wr);

	return false;
}

void *wr_skip(struct list_head *writes, struct rpc_write **wr_io,
		     unsigned int n)
{
	struct rpc_write *wr = *wr_io;
	void *buf;

	if (n > wr_free_space(wr)) {
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
	    memcmp(ent->host_addr, host_addr, HOST_ADDR_MAX_LEN))
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
	memcpy(drc->host_addr, host_addr, HOST_ADDR_MAX_LEN);

	g_hash_table_replace(request_cache, (void *) hash, drc);
}

#if 0 /* needed someday? see FIXME in srv_space_used() */
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
#endif

uint64_t srv_space_used(void)
{
	static uint64_t cached_total;
	static uint64_t ttl;
	uint64_t total = 0;

	if (ttl && cached_total && (current_time.tv_sec < ttl))
		return cached_total;

	/* FIXME: iterate through inodes, calc space used */

	cached_total = total;
	ttl = current_time.tv_sec + SRV_SPACE_USED_TTL;

	return total;
}

static void gc_timer_add(void)
{
	struct timeval tv;

	tv.tv_sec = SRV_GARBAGE_TIME;
	tv.tv_usec = 0;

	if (evtimer_add(&garbage_timer, &tv) < 0)
		syslog(LOG_ERR, "evtimer_add(garbage) failed");
}

static void garbage_collect(int fd, short events, void *userdata)
{
	if (debugging)
		syslog(LOG_DEBUG, "Garbage collection");

	drc_gc();
	state_gc();

	gc_timer_add();
}

static bool rpc_msg(struct rpc_cxn *cxn, void *msg, unsigned int msg_len)
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

	hash = blob_hash(BLOB_HASH_INIT, msg, MIN(msg_len, 128));

	xid = CR32();			/* xid */

	drc = drc_lookup(hash, xid, cxn->host_addr);
	if (drc) {
		srv.stats.drc_hits++;
		drc->expire = current_time.tv_sec + SRV_DRC_TIME;

		if (cxn_writeq(cxn, drc->val, drc->len, NULL, NULL)) {
			cxn->state = evt_dispose;
			return true;
		}

		if (debugging > 1)
			syslog(LOG_DEBUG, "RPC DRC cache hit (%u bytes)",
			       drc->len);

		return cxn_write_start(cxn);
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

	{
		uint32_t rpc_ver = CR32();
		uint32_t rpc_prog = CR32();
		uint32_t rpc_pver = CR32();

		if ((rpc_ver != 2) ||			/* rpc version */
		    (rpc_prog != NFS4_PROGRAM) ||	/* rpc program */
		    (rpc_pver != NFS_V4))	{	/* rpc program version*/
			if (debugging > 1)
				syslog(LOG_DEBUG, "RPC: invalid msg hdr (ver %u, prog %u, prog vers %u",
					rpc_ver, rpc_prog, rpc_pver);
			goto err_out;
		}
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
		drc_mask = nfsproc_null(cxn->host, &auth_cred, &auth_verf, cur,
					writes, wr);
		break;
	case NFSPROC4_COMPOUND:
		srv.stats.proc_compound++;
		drc_mask = nfsproc_compound(cxn->host, &auth_cred, &auth_verf,
					    cur, writes, wr);
		break;
	default:
		goto err_out;
	}

	/*
	 * send response back to client asynchronously
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
		n_writes++;
		list_del(&_wr->node);

		if (_wr->len) {
			if (cxn_writeq(cxn, _wr->buf, _wr->len,
					wr_done_cb, _wr)) {
				/* FIXME: leak several _wr's on err */
				cxn->state = evt_dispose;
				goto err_out;
			}

			if (cache) {
				memcpy(cache + cache_used, _wr->buf, _wr->len);
				cache_used += _wr->len;
			}

			n_wbytes += _wr->len;
		} else
			wr_free(_wr);
	}

	srv.stats.sock_tx_bytes += n_wbytes;

	if (cache)
		drc_store(hash, cache, cache_len, xid, cxn->host_addr);

	if (debugging > 1)
		syslog(LOG_DEBUG, "RPC reply: %u bytes, %u writes",
			n_wbytes, n_writes);

	return cxn_write_start(cxn);

err_out:
	if (debugging > 1)
		syslog(LOG_DEBUG, "RPC: invalid message (%u bytes, xid %x), "
		       "ignoring",
		       msg_len, xid);

	return cxn_write_start(cxn);
}

static bool cxn_write_free(struct rpc_cxn *cxn, struct rpc_cxn_write *tmp,
			   bool done)
{
	bool rcb = false;

	if (tmp->cb)
		rcb = tmp->cb(cxn, tmp, done);
	list_del(&tmp->node);
	free(tmp);

	return rcb;
}

static void rpc_cxn_free(struct rpc_cxn *cxn)
{
	struct rpc_cxn_write *rpcwr, *iter;

	if (cxn->fd >= 0)
		close(cxn->fd);
	free(cxn->msg);
	g_free(cxn->host);

	list_for_each_entry_safe(rpcwr, iter, &cxn->write_q, node) {
		cxn_write_free(cxn, rpcwr, false);
	}

	syslog(LOG_INFO, "%s disconnect", cxn->host_addr);

	memset(cxn, 0, sizeof(*cxn));
	free(cxn);
}

static void cxn_writable(struct rpc_cxn *cxn)
{
	unsigned int n_iov = 0;
	struct rpc_cxn_write *tmp;
	ssize_t rc;
	struct iovec iov[CLI_MAX_WR_IOV];
	bool more_work;

restart:
	more_work = false;

	/* accumulate pending writes into iovec */
	list_for_each_entry(tmp, &cxn->write_q, node) {
		/* bleh, struct iovec should declare iov_base const */
		iov[n_iov].iov_base = (void *) tmp->buf;
		iov[n_iov].iov_len = tmp->len;
		n_iov++;
		if (n_iov == CLI_MAX_WR_IOV)
			break;
	}

	/* execute non-blocking write */
do_write:
	rc = writev(cxn->fd, iov, n_iov);
	if (rc < 0) {
		if (errno == EINTR)
			goto do_write;
		if (errno != EAGAIN)
			cxn->state = evt_dispose;
		return;
	}

	/* iterate through write queue, issuing completions based on
	 * amount of data written
	 */
	while (rc > 0) {
		int sz;

		/* get pointer to first record on list */
		tmp = list_entry(cxn->write_q.next, struct rpc_cxn_write, node);

		/* mark data consumed by decreasing tmp->len */
		sz = (tmp->len < rc) ? tmp->len : rc;
		tmp->len -= sz;
		rc -= sz;

		/* if tmp->len reaches zero, write is complete,
		 * call callback and clean up
		 */
		if (tmp->len == 0)
			if (cxn_write_free(cxn, tmp, true))
				more_work = true;
	}

	if (more_work)
		goto restart;

	/* if we emptied the queue, clear write notification */
	if (list_empty(&cxn->write_q)) {
		cxn->writing = false;

		if (event_del(&cxn->write_ev) < 0) {
			syslog(LOG_WARNING, "cxn_writable event_del");
			cxn->state = evt_dispose;
			return;
		}
	}
}

static bool cxn_write_start(struct rpc_cxn *cxn)
{
	if (list_empty(&cxn->write_q))
		return true;		/* loop, not poll */

	/* if EV_WRITE already active, nothing further to do */
	if (cxn->writing)
		return false;		/* poll wait */

	/* attempt optimistic write, in hopes of avoiding poll,
	 * or at least refill the write buffers so as to not
	 * get -immediately- called again by the kernel
	 */
	cxn_writable(cxn);
	if (list_empty(&cxn->write_q)) {
		srv.stats.opt_write++;
		return true;		/* loop, not poll */
	}

	if (event_add(&cxn->write_ev, NULL) < 0) {
		syslog(LOG_WARNING, "cxn_write_start event_add");
		return true;		/* loop, not poll */
	}

	cxn->writing = true;

	return false;			/* poll wait */
}

static int cxn_writeq(struct rpc_cxn *cxn, const void *buf, unsigned int buflen,
		      cxn_write_func cb, void *cb_data)
{
	struct rpc_cxn_write *wr;

	if (!buf || !buflen)
		return -EINVAL;

	wr = malloc(sizeof(struct rpc_cxn_write));
	if (!wr)
		return -ENOMEM;

	wr->buf = buf;
	wr->len = buflen;
	wr->cb = cb;
	wr->cb_data = cb_data;
	list_add_tail(&wr->node, &cxn->write_q);

	return 0;
}

static bool cxn_evt_dispose(struct rpc_cxn *cxn, short events)
{
	/* if write queue is not empty, we should continue to get
	 * poll callbacks here until it is
	 */
	if (list_empty(&cxn->write_q))
		rpc_cxn_free(cxn);

	return false;
}

static bool cxn_evt_get_hdr(struct rpc_cxn *cxn, short events)
{
	uint32_t next_frag;
	ssize_t rrc;
	void *mem;

	rrc = read(cxn->fd, cxn->hdr + cxn->hdr_used,
		   sizeof(cxn->hdr) - cxn->hdr_used);
	if (rrc < 0) {
		if (errno == EAGAIN)
			return false;	/* read more data */
		syslogerr(cxn->host_addr);
		goto err_out;
	}
	if (rrc == 0)
		return false;		/* read more data */

	srv.stats.sock_rx_bytes += rrc;
	cxn->hdr_used += rrc;

	if (cxn->hdr_used < sizeof(cxn->hdr))
		return false;		/* read more data */

	next_frag = ntohl(*(uint32_t *)cxn->hdr);
	if (next_frag & HDR_FRAG_END) {
		cxn->last_frag = true;
		next_frag &= ~HDR_FRAG_END;
	}
	if ((next_frag > MAX_FRAG_SZ) ||
	    ((next_frag + cxn->msg_len) > MAX_MSG_SZ))
		goto err_out;

	mem = realloc(cxn->msg, next_frag + cxn->msg_len);
	if (!mem)
		goto err_out;

	cxn->msg = mem;

	if (debugging > 1)
		syslog(LOG_DEBUG, "RPC frag (%u bytes%s)",
		       next_frag,
		       cxn->last_frag ? ", LAST" : "");

	cxn->hdr_used = 0;
	cxn->next_frag = next_frag;
	cxn->state = evt_get_data;

	return true;			/* loop to cxn->state */

err_out:
	cxn->state = evt_dispose;
	return true;			/* loop to cxn->state */
}

static bool cxn_evt_get_data(struct rpc_cxn *cxn, short events)
{
	ssize_t rrc;

	rrc = read(cxn->fd, cxn->msg + cxn->msg_len, cxn->next_frag);
	if (rrc < 0) {
		if (errno == EAGAIN)
			return false;	/* read more data */
		syslogerr(cxn->host_addr);
		goto err_out;
	}

	srv.stats.sock_rx_bytes += rrc;
	cxn->next_frag -= rrc;
	cxn->msg_len += rrc;

	if (cxn->next_frag)
		return false;		/* read more data */
	if (!cxn->last_frag) {
		cxn->state = evt_get_hdr;
		return false;		/* read more data */
	}

	cxn->state = evt_rpc_msg;
	return true;			/* loop to cxn->state */

err_out:
	cxn->state = evt_dispose;
	return true;			/* loop to cxn->state */
}

static bool cxn_evt_rpc_msg(struct rpc_cxn *cxn, short events)
{
	bool rc;

	/* set up next-state now; rpc_msg may override */
	cxn->state = evt_get_hdr;

	rc = rpc_msg(cxn, cxn->msg, cxn->msg_len);

	free(cxn->msg);
	cxn->msg = NULL;
	cxn->msg_len = 0;
	cxn->next_frag = 0;
	cxn->last_frag = false;

	return rc;			/* loop to cxn->state */
}

static cxn_evt_func state_funcs[] = {
	[evt_get_hdr]		= cxn_evt_get_hdr,
	[evt_get_data]		= cxn_evt_get_data,
	[evt_rpc_msg]		= cxn_evt_rpc_msg,
	[evt_dispose]		= cxn_evt_dispose,
};

static void tcp_cxn_wr_event(int fd, short events, void *userdata)
{
	cxn_writable(userdata);
}

static void tcp_cxn_event(int fd, short events, void *userdata)
{
	struct rpc_cxn *cxn = userdata;
	bool loop;

	do {
		loop = state_funcs[cxn->state](cxn, events);
	} while (loop);
}

static void tcp_srv_event(int fd, short events, void *userdata)
{
	struct server_socket *sock = userdata;
	socklen_t addrlen = sizeof(struct sockaddr_in6);
	struct rpc_cxn *cxn;
	char host[64];

	/* alloc and init client info */
	cxn = calloc(1, sizeof(*cxn));
	if (!cxn) {
		struct sockaddr_in6 a;
		int fd = accept(sock->fd, (struct sockaddr *) &a, &addrlen);
		close(fd);
		return;
	}

	cxn->state = evt_get_hdr;
	cxn->host = host;
	INIT_LIST_HEAD(&cxn->write_q);

	/* receive TCP connection from kernel */
	cxn->fd = accept(sock->fd, (struct sockaddr *) &cxn->addr, &addrlen);
	if (cxn->fd < 0) {
		syslogerr("tcp accept");
		goto err_out;
	}

	event_set(&cxn->ev, cxn->fd, EV_READ | EV_PERSIST, tcp_cxn_event, cxn);
	event_set(&cxn->write_ev, cxn->fd, EV_WRITE | EV_PERSIST,
		  tcp_cxn_wr_event, cxn);

	srv.stats.tcp_accept++;

	/* mark non-blocking, for upcoming libevent use */
	if (fsetflags("tcp client", cxn->fd, O_NONBLOCK) < 0)
		goto err_out_fd;

	/* add to libevent watchlist */
	if (event_add(&cxn->ev, NULL) < 0) {
		syslog(LOG_WARNING, "tcp client event_add");
		goto err_out_fd;
	}

	/* pretty-print incoming cxn info */
	getnameinfo((struct sockaddr *) &cxn->addr, sizeof(struct sockaddr_in6),
		    host, sizeof(host), NULL, 0, NI_NUMERICHOST);
	host[sizeof(host) - 1] = 0;
	syslog(LOG_INFO, "client %s connected", host);

	strcpy(cxn->host_addr, host);

	return;

err_out_fd:
	close(cxn->fd);
err_out:
	free(cxn);
}

static int net_open(void)
{
	int ipv6_found;
	int rc;
	struct addrinfo hints, *res, *res0;
	char port_str[32];

	sprintf(port_str, "%u", opt_nfs_port);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	rc = getaddrinfo(NULL, port_str, &hints, &res0);
	if (rc) {
		syslog(LOG_ERR, "getaddrinfo(*:%s) failed: %s",
		       port_str, gai_strerror(rc));
		rc = -EINVAL;
		goto err_addr;
	}

	/*
	 * We rely on getaddrinfo to discover if the box supports IPv6.
	 * Much easier to sanitize its output than to try to figure what
	 * to put into ai_family.
	 *
	 * These acrobatics are required on Linux because we should bind
	 * to ::0 if we want to listen to both ::0 and 0.0.0.0. Else, we
	 * may bind to 0.0.0.0 by accident (depending on order getaddrinfo
	 * returns them), then bind(::0) fails and we only listen to IPv4.
	 */
	ipv6_found = 0;
	for (res = res0; res; res = res->ai_next) {
		if (res->ai_family == PF_INET6)
			ipv6_found = 1;
	}

	for (res = res0; res; res = res->ai_next) {
		struct server_socket *sock;
		int fd, on;

		if (ipv6_found && res->ai_family == PF_INET)
			continue;

		fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (fd < 0) {
			syslogerr("tcp socket");
			return -errno;
		}

		on = 1;
		if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on,
			       sizeof(on)) < 0) {
			syslogerr("setsockopt(SO_REUSEADDR)");
			rc = -errno;
			goto err_out;
		}

		if (bind(fd, res->ai_addr, res->ai_addrlen) < 0) {
			syslogerr("tcp bind");
			rc = -errno;
			goto err_out;
		}

		if (listen(fd, LISTEN_SIZE) < 0) {
			syslogerr("tcp listen");
			rc = -errno;
			goto err_out;
		}

		rc = fsetflags("tcp server", fd, O_NONBLOCK);
		if (rc)
			goto err_out;

		sock = calloc(1, sizeof(*sock));
		if (!sock) {
			rc = -ENOMEM;
			goto err_out;
		}

		sock->fd = fd;

		event_set(&sock->ev, fd, EV_READ | EV_PERSIST,
			  tcp_srv_event, sock);

		if (event_add(&sock->ev, NULL) < 0) {
			syslog(LOG_WARNING, "tcp socket event_add failed");
			rc = -EINVAL;
			goto err_out;
		}

		srv.sockets =
			g_list_append(srv.sockets, sock);
	}

	freeaddrinfo(res0);

	return 0;

err_out:
	freeaddrinfo(res0);
err_addr:
	return rc;
}

static int init_server(void)
{
	struct timezone tz = { 0, 0 };
	int rc;

	rc = write_pid_file(pid_fn);
	if (rc)
		return rc;

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
	srv.data_dir = opt_data_path;
	srv.metadata_dir = opt_metadata;
	srv.fsdb.home = srv.metadata_dir;
	srv.fsdb.txn_nosync = opt_txn_nosync;

	if (gettimeofday(&current_time, &tz) < 0) {
		syslogerr("gettimeofday(2)");
		return -errno;
	}

	if (!srv.clid_idx || !srv.openfiles || !request_cache) {
		syslog(LOG_ERR, "OOM in init_server()");
		return -ENOMEM;
	}

	rc = fsdb_open(&srv.fsdb, DB_RECOVER | DB_CREATE, DB_CREATE,
		       "nfs4d", true);
	if (rc)
		return rc;

	init_rngs();
	rand_verifier(&srv.instance_verf);

	evtimer_set(&garbage_timer, garbage_collect, NULL);
	gc_timer_add();

	rc = net_open();

	return rc;
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
	case 'D':
		if (!is_dir(arg, &opt_data_path))
			argp_usage(state);
		break;
	case 'M':
		if (!is_dir(arg, &opt_metadata))
			argp_usage(state);
		break;
	case 'O':
		opt_lcldom = arg;
		break;
	case 'f':
		opt_foreground = true;
		break;
	case 'N':
		opt_txn_nosync = true;
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
	server_running = false;
	event_loopbreak();
}

static void stats_signal(int signal)
{
	dump_stats = true;
	event_loopbreak();
}

static void stats_dump(void)
{
	struct timezone tz = { 0, 0 };
	int fd;
	char *stats_str;

	gettimeofday(&current_time, &tz);

	asprintf(&stats_str,
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
		"tcp_accept: %lu\n"
		"event: %lu\n"
		"max_evt: %lu\n"
		"poll: %lu\n"
		"opt_write: %lu\n"
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
		srv.stats.tcp_accept,
		srv.stats.event,
		srv.stats.max_evt,
		srv.stats.poll,
		srv.stats.opt_write,
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
		return;
	}

	if (write(fd, stats_str, strlen(stats_str)) < 0) {
		syslog(LOG_ERR, "write(%s, %lu): %s",
		       stats_fn,
		       (unsigned long) strlen(stats_str),
		       strerror(errno));
		close(fd);
		return;
	}

	if (close(fd) < 0)
		syslog(LOG_ERR, "close(%s): %s", stats_fn, strerror(errno));
}

static void srv_exit_cleanup(void)
{
	if (pid_opened && unlink(pid_fn) < 0)
		syslogerr("unlink");
}

int main (int argc, char *argv[])
{
	error_t aprc;
	char debugstr[64];

	setlocale(LC_ALL, "");

	argp_program_version = PACKAGE_VERSION;
	argp_err_exit_status = EXIT_FAILURE;

	aprc = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (aprc) {
		fprintf(stderr, "argp_parse failed: %s\n", strerror(aprc));
		return 1;
	}

	atexit(srv_exit_cleanup);
	signal(SIGHUP, SIG_IGN);
	signal(SIGPIPE, SIG_IGN);
	signal(SIGINT, term_signal);
	signal(SIGTERM, term_signal);
	signal(SIGUSR1, stats_signal);

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
		syslogerr("daemon(2)");
		return 1;
	}

	event_init();

	if (init_server())
		return 1;

	if (debugging)
		sprintf(debugstr, " (DEBUG MODE %d)", debugging);
	else
		debugstr[0] = 0;

	syslog(LOG_INFO, PACKAGE_STRING " initialized%s", debugstr);

	while (server_running) {
		event_dispatch();

		if (dump_stats) {
			dump_stats = false;
			stats_dump();
		}
	}

	fsdb_close(&srv.fsdb);

	syslog(LOG_INFO, "server exit");
	return 0;
}

