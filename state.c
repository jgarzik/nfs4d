
#define _GNU_SOURCE
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include <glib.h>
#include "nfs4_prot.h"
#include "server.h"
#include "elist.h"

struct nfs_clientid {
	struct blob		id;
	verifier4		cli_verf;	/* client-supplied verifier */
	clientid4		id_short;
	verifier4		confirm_verf;	/* clientid confirm verifier */
	cb_client4		callback;
	uint32_t		callback_ident;

	bool			pending;

	struct list_head	node;
};

struct nfs_client {
	struct nfs_clientid	*id;

	struct nfs_timer	timer;

	struct list_head	pending;	/* unconfirmed requests */
};

static void client_cancel(clientid4 cli);

/* "djb2"-derived hash function */
unsigned long blob_hash(unsigned long hash, const void *_buf, size_t buflen)
{
	const unsigned char *buf = _buf;
	int c;

	g_assert(buf != NULL);

	while (buflen > 0) {
		c = *buf++;
		buflen--;

		hash = ((hash << 5) + hash) ^ c; /* hash * 33 ^ c */
	}

	return hash;
}

static unsigned long blob_hash_for_key(const struct blob *b)
{
	g_assert(b != NULL);
	g_assert(b->magic == BLOB_MAGIC);

	return blob_hash(BLOB_HASH_INIT, b->buf, b->len);
}

static bool blob_equal(const struct blob *a, const struct blob *b)
{
	g_assert(a != NULL);
	g_assert(a->magic == BLOB_MAGIC);
	g_assert(b != NULL);
	g_assert(b->magic == BLOB_MAGIC);

	if (a->len != b->len)
		return false;
	if (memcmp(a->buf, b->buf, a->len))
		return false;
	return true;
}

static void nrand32(void *mem, unsigned int dwords)
{
	uint32_t *v = mem;
	long l;
	int i;

	for (i = 0; i < dwords; i++) {
		l = 0;
		lrand48_r(&srv.rng, &l);

		v[i] = l;
	}
}

void rand_verifier(verifier4 *verf)
{
	nrand32(verf, 5);
}

uint32_t gen_stateid(void)
{
	int loop = 1000000;
	uint32_t tmp = 0;

	do {
		if (G_UNLIKELY(loop == 0)) {
			syslog(LOG_ERR, "gen_stateid: 1,000,000 collisions");
			return 0;
		}

		loop--;

		nrand32(&tmp, 1);
	} while (g_hash_table_lookup(srv.state, GUINT_TO_POINTER(tmp)) != NULL);

	return tmp;
}

nfsstat4 stateid_lookup(uint32_t id, nfsino_t ino, enum nfs_state_type type,
			struct nfs_state **st_out)
{
	struct nfs_state *st;

	*st_out = NULL;

	st = g_hash_table_lookup(srv.state, GUINT_TO_POINTER(id));
	if (!st)
		return NFS4ERR_STALE_STATEID;

	if ((st->type == nst_dead) && (type != nst_dead))
		return NFS4ERR_OLD_STATEID;

	if ((type != nst_any) && (st->type != type))
		return NFS4ERR_BAD_STATEID;
	if (ino && (ino != st->ino))
		return NFS4ERR_BAD_STATEID;

	clientid_touch(st->cli);

	*st_out = st;
	return NFS4_OK;
}

struct state_search_info {
	bool			write;
	bool			write_deny;
	nfsino_t		ino;
	uint64_t		ofs;
	uint64_t		len;

	nfsstat4		status;
	struct nfs_state	*match;
	struct nfs_state	*self;
};

static void access_search(gpointer key, gpointer val, gpointer user_data)
{
	struct nfs_state *st = val;
	struct state_search_info *ssi = user_data;

	if (ssi->ino != st->ino)
		return;

	switch (st->type) {

	case nst_open: {
		unsigned int bit, dbit;

		if (ssi->write)
			bit = OPEN4_SHARE_ACCESS_WRITE;
		else
			bit = OPEN4_SHARE_ACCESS_READ;
		if (ssi->write_deny)
			dbit = OPEN4_SHARE_DENY_WRITE;
		else
			dbit = OPEN4_SHARE_DENY_READ;

		if ((st->u.share.deny & bit) && ssi->self && (st != ssi->self)) {
			ssi->match = st;
			ssi->status = NFS4ERR_SHARE_DENIED;
		} else if ((st->u.share.access & dbit) && ssi->self && (st != ssi->self)) {
			ssi->match = st;
			ssi->status = NFS4ERR_SHARE_DENIED;
		} else if ((st == ssi->self) && (!(st->u.share.access & bit))) {
			ssi->match = st;
			ssi->status = NFS4ERR_OPENMODE;
		}
		break;
	}

	case nst_lock: {
		struct nfs_lock *lock;
		uint64_t ssi_end_ofs, end_ofs;

		if (ssi->len == 0xffffffffffffffffULL)
			ssi_end_ofs = 0xffffffffffffffffULL;
		else
			ssi_end_ofs = ssi->ofs + ssi->len;

		list_for_each_entry(lock, &st->u.lock.list, node) {
			if (lock->len == 0xffffffffffffffffULL)
				end_ofs = 0xffffffffffffffffULL;
			else
				end_ofs = lock->ofs + lock->len;

			if (ssi_end_ofs <= lock->ofs)
				continue;
			if (end_ofs <= ssi->ofs)
				continue;
			if (!ssi->write &&
			    ((lock->type == READ_LT) ||
			     (lock->type == READW_LT)))
				continue;

			ssi->match = st;
			ssi->status = NFS4ERR_DENIED;
		}
		break;
	}

	case nst_any:
	case nst_dead:
		/* do nothing */
		return;
	}
}

nfsstat4 access_ok(struct nfs_stateid *sid, nfsino_t ino, bool write,
		  bool write_deny,
		  uint64_t ofs, uint64_t len, struct nfs_state **st_out,
		  struct nfs_state **conflict_st_out)
{
	struct nfs_state *st = NULL;
	struct state_search_info ssi = { write, write_deny, ino, ofs, len,
					 NFS4_OK, };

	if (st_out)
		*st_out = NULL;

	if (sid && (sid->seqid != 0) && (sid->seqid != 0xffffffffU)) {
		nfsstat4 status = stateid_lookup(sid->id, ino, nst_any, &st);
		if (status != NFS4_OK)
			return status;
	}

	ssi.self = st;
	g_hash_table_foreach(srv.state, access_search, &ssi);

	if (st_out)
		*st_out = st;
	if (conflict_st_out)
		*conflict_st_out = ssi.match;

	return ssi.status;
}

static void state_trash_locks(struct nfs_state *st)
{
	struct nfs_lock *tmp, *iter;

	list_for_each_entry_safe(tmp, iter, &st->u.lock.list, node) {
		list_del(&tmp->node);

		memset(tmp, 0, sizeof(*tmp));
		free(tmp);
	}

	st->u.lock.open = NULL;
}

void state_trash(struct nfs_state *st)
{
	bool rc;

	if (st->type == nst_lock)
		state_trash_locks(st);

	st->type = nst_dead;
	INIT_LIST_HEAD(&st->u.dead_node);
	list_add_tail(&st->u.dead_node, &srv.dead_state);
	srv.n_dead++;

	if (srv.n_dead < SRV_STATE_HIGH_WAT)
		return;

	while (srv.n_dead > SRV_STATE_LOW_WAT) {
		st = list_entry(srv.dead_state.next, struct nfs_state, u.dead_node);

		/* removing from hash table frees struct */
		rc = g_hash_table_remove(srv.state, GUINT_TO_POINTER(st->id));
		if (!rc) {
			syslog(LOG_ERR, "failed to GC state(ID:%u)", st->id);
			state_free(st);
		}

		srv.n_dead--;
	}

	if (debugging)
		syslog(LOG_INFO, "state garbage collected");
}

struct nfs_state *state_new(enum nfs_state_type type, struct nfs_buf *owner)
{
	struct nfs_state *st;

	st = calloc(1, sizeof(struct nfs_state));
	if (!st)
		return NULL;

	st->type = type;
	st->id = gen_stateid();
	if (!st->id) {
		free(st);
		return NULL;
	}

	st->owner = strndup(owner->val, owner->len);
	if (!st->owner) {
		free(st);
		return NULL;
	}

	switch (type) {
	case nst_any:
	case nst_open:
		/* do nothing */
		break;

	case nst_dead:
		INIT_LIST_HEAD(&st->u.dead_node);
		break;

	case nst_lock:
		INIT_LIST_HEAD(&st->u.lock.list);
		break;
	}

	return st;
}

static void gen_clientid4(clientid4 *id)
{
	int loop = 1000000;
	memset(id, 0, sizeof(*id));

	do {
		if (G_UNLIKELY(loop == 0)) {
			syslog(LOG_ERR, "gen_clientid: 1,000,000 collisions");
			return;
		}

		loop--;

		nrand32(id, 2);
	} while (g_hash_table_lookup(srv.clid_idx,
				(void *)((unsigned long) *id)) != NULL);
}

bool clientid_touch(clientid4 id_in)
{
	struct nfs_client *cli;
	unsigned long id = (unsigned long) id_in;

	cli = g_hash_table_lookup(srv.clid_idx, (void *) id);
	if (!cli)
		return false;

	timer_renew(&cli->timer, SRV_LEASE_TIME);

	return true;
}

nfsstat4 clientid_test(clientid4 id_in)
{
	struct nfs_client *cli;
	unsigned long id = (unsigned long) id_in;

	cli = g_hash_table_lookup(srv.clid_idx, (void *) id);
	if (!cli)
		return NFS4ERR_BADOWNER;
	if (!cli->id)
		return NFS4ERR_STALE_CLIENTID;
	return NFS4_OK;
}

static int copy_cb_client4(cb_client4 *dest, const cb_client4 *src)
{
	int rc = -ENOMEM;

	dest->cb_program = src->cb_program;

	dest->cb_location.r_netid = strdup(src->cb_location.r_netid);
	if (!dest->cb_location.r_netid)
		goto err_out;

	dest->cb_location.r_addr = strdup(src->cb_location.r_addr);
	if (!dest->cb_location.r_addr)
		goto err_out_1;

	return 0;

err_out_1:
	free(dest->cb_location.r_netid);
err_out:
	return rc;
}

static void free_cb_client4(cb_client4 *cbc)
{
	free(cbc->cb_location.r_netid);
	free(cbc->cb_location.r_addr);
}

static void clientid_free(struct nfs_clientid *clid)
{
	if (!clid)
		return;

	if (clid->pending)
		list_del(&clid->node);

	g_hash_table_remove(srv.client_ids, &clid->id);

	free(clid->id.buf);
	free_cb_client4(&clid->callback);

	memset(clid, 0, sizeof(*clid));
	free(clid);
}

void state_free(gpointer data)
{
	struct nfs_state *st = data;

	if (!st)
		return;

	free(st->owner);

	switch (st->type) {
	case nst_any:
		/* invalid type, should never happen */
		/* fall through */

	case nst_open:
		/* do nothing */
		break;
	case nst_dead:
		list_del(&st->u.dead_node);
		break;
	case nst_lock:
		state_trash_locks(st);
		break;
	}

	memset(st, 0, sizeof(*st));
	free(st);
}

void client_free(gpointer data)
{
	struct nfs_client *cli = data;
	struct nfs_clientid *tmp, *iter_tmp;

	if (!cli)
		return;

	clientid_free(cli->id);

	list_for_each_entry_safe(tmp, iter_tmp, &cli->pending, node) {
		clientid_free(tmp);
	}

	memset(cli, 0, sizeof(*cli));
	free(cli);
}

guint clientid_hash(gconstpointer key)
{
	const struct blob *blob = key;
	return blob_hash_for_key(blob);
}

gboolean clientid_equal(gconstpointer _a, gconstpointer _b)
{
	const struct blob *a = _a;
	const struct blob *b = _b;
	return blob_equal(a, b);
}

static int clientid_new(struct nfs_client *cli, struct nfs_cxn *cxn,
			struct nfs_buf *id_long, verifier4 *client_verf,
			uint32_t cb_ident, cb_client4 *callback,
			struct nfs_clientid **clid_out)
{
	struct nfs_clientid *clid;
	unsigned long short_clid;

	clid = calloc(1, sizeof(struct nfs_clientid));
	if (!clid)
		goto err_out;

	INIT_LIST_HEAD(&clid->node);

	/* copy client id */
	clid->id.magic = BLOB_MAGIC;
	clid->id.len = id_long->len;
	clid->id.buf = malloc(clid->id.len);
	if (!clid->id.buf)
		goto err_out_clid;
	memcpy(clid->id.buf, id_long->val, clid->id.len);

	/* copy client verifier */
	memcpy(&clid->cli_verf, client_verf, sizeof(verifier4));

	/* generate shorthand client id, random SETCLIENTID_CONFIRM verifier */
	gen_clientid4(&clid->id_short);
	rand_verifier(&clid->confirm_verf);

	/* copy callback info */
	if (copy_cb_client4(&clid->callback, callback))
		goto err_out_clid_buf;
	clid->callback_ident = cb_ident;

	short_clid = (unsigned long) clid->id_short;

	/* add to short, long client id indices */
	g_hash_table_insert(srv.clid_idx, (void *) short_clid, cli);
	g_hash_table_insert(srv.client_ids, &clid->id, cli);

	*clid_out = clid;
	return 0;

err_out_clid_buf:
	free(clid->id.buf);
err_out_clid:
	free(clid);
err_out:
	return -ENOMEM;
}

static void client_timer(struct nfs_timer *timer, void *priv)
{
	struct nfs_client *cli = priv;

	if (!cli->id) {
		syslog(LOG_ERR, "BUG: null cli->id in client_timer()");
		return;
	}

	syslog(LOG_INFO, "timeout, cancelling state for CID:%Lx",
		(unsigned long long) cli->id->id_short);
	client_cancel(cli->id->id_short);
}

static int client_new(struct nfs_cxn *cxn,
			struct nfs_buf *id_long, verifier4 *client_verf,
			uint32_t cb_ident, cb_client4 *callback,
			struct nfs_clientid **clid_out)
{
	struct nfs_client *cli;
	struct nfs_clientid *clid = NULL;
	int rc = -ENOMEM;

	cli = calloc(1, sizeof(struct nfs_client));
	if (!cli)
		goto err_out;

	INIT_LIST_HEAD(&cli->pending);

	timer_init(&cli->timer, client_timer, cli);

	rc = clientid_new(cli, cxn, id_long, client_verf, cb_ident,
			  callback, &clid);
	if (rc)
		goto err_out_st;

	/* add to state's client-id pending list */
	clid->pending = true;
	list_add(&clid->node, &cli->pending);

	*clid_out = clid;
	return 0;

err_out_st:
	free(cli);
err_out:
	return rc;
}

struct cancel_search {
	clientid4		cli;
	GList			*list;
};

static void cli_cancel_search(gpointer key, gpointer val, gpointer user_data)
{
	struct nfs_state *st = val;
	struct cancel_search *cs = user_data;

	if (st->cli == cs->cli)
		cs->list = g_list_append(cs->list, st);
}

static void client_cancel(clientid4 cli)
{
	struct cancel_search cs = { cli };
	struct nfs_state *st;
	unsigned int trashed = 0;
	GList *tmp;

	/* build list of state records associated with this client */
	g_hash_table_foreach(srv.state, cli_cancel_search, &cs);

	/* destroy each state record */
	tmp = cs.list;
	while (tmp) {
		st = tmp->data;
		tmp = tmp->next;

		state_trash(st);
	}

	g_list_free(cs.list);

	if (debugging)
		syslog(LOG_INFO,
		       "binned %u state recs associated with CID:%Lx",
		       trashed, (unsigned long long) cli);
}

static bool callback_equal(struct nfs_client *cli, cb_client4 *cb,
			       uint32_t cb_ident)
{
	struct nfs_clientid *clid;

	if (!cli)
		return false;
	if (!cli->id)
		return false;

	clid = cli->id;
	if (clid->callback_ident != cb_ident)
		return false;
	if (clid->callback.cb_program != cb->cb_program)
		return false;
	if (!cb->cb_location.r_addr || !cb->cb_location.r_netid)
		return false;
	if (strcmp(clid->callback.cb_location.r_netid,
		   cb->cb_location.r_netid))
		return false;
	if (strcmp(clid->callback.cb_location.r_addr,
		   cb->cb_location.r_addr))
		return false;

	return true;
}

nfsstat4 nfs_op_setclientid(struct nfs_cxn *cxn, struct curbuf *cur,
			    struct list_head *writes, struct rpc_write **wr)
{
	nfsstat4 status = NFS4_OK;
	struct nfs_client *cli;
	int rc;
	struct nfs_clientid *clid = NULL;
	struct blob clid_key;
	struct nfs_buf client, tmpstr;
	verifier4 *client_verf;
	const char *msg = "(err)";
	uint32_t cb_ident;
	cb_client4 callback;

	client_verf = CURMEM(sizeof(verifier4));
	CURBUF(&client);

	memset(&callback, 0, sizeof(callback));

	callback.cb_program = CR32();	/* cb_program */
	CURBUF(&tmpstr);		/* r_netid */
	if (tmpstr.len)
		callback.cb_location.r_netid = strndup(tmpstr.val, tmpstr.len);
	CURBUF(&tmpstr);		/* r_addr */
	if (tmpstr.len)
		callback.cb_location.r_addr = strndup(tmpstr.val, tmpstr.len);
	cb_ident = CR32();		/* callback_ident */

	/* look up client id */
	clid_key.magic = BLOB_MAGIC;
	clid_key.len = client.len;
	clid_key.buf = client.val;
	cli = g_hash_table_lookup(srv.client_ids, &clid_key);

	if (!cli) {
		rc = client_new(cxn, &client, client_verf, cb_ident,
				&callback, &clid);
		if (rc < 0) {
			status = NFS4ERR_RESOURCE;
			goto out;
		}

		msg = "NEW";
	}

	else if ((!cli->id) ||
		 (memcmp(&cli->id->cli_verf, client_verf, sizeof(verifier4))) ||
		 (!callback_equal(cli, &callback, cb_ident))) {

		rc = clientid_new(cli, cxn, &client, client_verf,
				  cb_ident, &callback, &clid);
		if (rc < 0) {
			status = NFS4ERR_RESOURCE;
			goto out;
		}

		/* add to state's client-id pending list */
		clid->pending = true;
		list_add(&clid->node, &cli->pending);

		msg = "EXIST";
	}

	else {
		clid = cli->id;

		msg = "PEND";
	}

out:
	if (debugging)
		syslog(LOG_INFO, "op SETCLIENTID (ID:%.*s "
		       "PROG:%u NET:%s ADDR:%s CBID:%u ACT:%s)",
		       client.len,
		       client.val,
		       callback.cb_program,
		       callback.cb_location.r_netid,
		       callback.cb_location.r_addr,
		       cb_ident,
		       msg);

	WR32(status);
	if (status == NFS4_OK) {
		g_assert(clid != NULL);

		WR64(clid->id_short);
		WRMEM(&clid->confirm_verf, sizeof(verifier4));

		if (debugging)
			syslog(LOG_INFO, "   SETCLIENTID -> CLID:%Lx",
				(unsigned long long) clid->id_short);
	}
	else if (status == NFS4ERR_CLID_INUSE) {
		/* FIXME return clientaddr4 client_using */
		syslog(LOG_ERR, "SETCLIENTID FIXME: return clientaddr4 client_using");
	}
	return status;
}

static bool confirm_equal(const struct nfs_clientid *a,
			  const struct nfs_clientid *b)
{
	if ((a->id_short == b->id_short) &&
	    (!memcmp(&a->confirm_verf, &b->confirm_verf,
	    	     sizeof(verifier4))))
		return true;

	return false;
}

nfsstat4 nfs_op_setclientid_confirm(struct nfs_cxn *cxn, struct curbuf *cur,
			    struct list_head *writes, struct rpc_write **wr)
{
	nfsstat4 status = NFS4_OK;
	struct nfs_client *cli;
	struct nfs_clientid *clid, *new_clid, *tmp_clid, clid_key;
	verifier4 *confirm_verf;
	clientid4 id_short;

	id_short = CR64();
	confirm_verf = CURMEM(sizeof(verifier4));

	if (debugging)
		syslog(LOG_INFO, "op SETCLIENTID_CONFIRM (ID:%Lx)",
		       (unsigned long long) id_short);

	/* get state record from clientid4 */
	cli = g_hash_table_lookup(srv.clid_idx,
			(void *)(unsigned long) id_short);
	if (!cli) {
		status = NFS4ERR_STALE_CLIENTID;
		goto out;
	}

	/* filter out duplicates */
	clid = cli->id;
	if (clid && (clid->id_short == id_short) &&
	    (!memcmp(&clid->confirm_verf, confirm_verf, sizeof(verifier4)))) {
		/* duplicate, just return success */
		if (debugging)
			syslog(LOG_INFO, "   SETCLIENTID_CONFIRM dup, ignoring");
		goto out;
	}

	/*
	 * find the matching unconfirmed record (if any), and
	 * remove it from the unconfirmed list.
	 */
	clid_key.id_short = id_short;
	memcpy(&clid_key.confirm_verf, confirm_verf, sizeof(verifier4));

	new_clid = NULL;
	list_for_each_entry(tmp_clid, &cli->pending, node) {
		if (confirm_equal(&clid_key, tmp_clid)) {
			new_clid = tmp_clid;
			break;
		}
	}
	if (!new_clid) {
		status = NFS4ERR_STALE_CLIENTID;
		goto out;
	}

	new_clid->pending = false;
	list_del(&new_clid->node);

	/*
	 * if old and new shorthand client ids are the same,
	 * we are just updating the callback
	 */
	if (clid && (clid->id_short == new_clid->id_short)) {
		/*
		 * FIXME: signal <not-yet-written code> to tear down
		 * the existing connection to the client
		 */

		if (debugging)
			syslog(LOG_INFO, "   SETCLIENTID_CONFIRM: updating callback");
		goto out2;
	}

	/*
	 * if no pre-existing state exists, we are done
	 */
	if (!clid) {
		if (debugging)
			syslog(LOG_INFO, "   SETCLIENTID_CONFIRM: no previous state.  confirmed.");
		goto out2;
	}

	/*
	 * If we get this far, the client requires recovery.  Start
	 * the process of recovering locks, leases, etc.
	 */

	/* FIXME: probably need to do more than just forget state */
	client_cancel(clid->id_short);

out2:
	if (clid) {
		unsigned long id_short = (unsigned long) clid->id_short;
		g_hash_table_replace(srv.clid_idx, (void *) id_short, NULL);
		clientid_free(clid);
	}
	cli->id = new_clid;
	g_hash_table_insert(srv.client_ids, &new_clid->id, cli);

out:
	WR32(status);
	return status;
}

nfsstat4 nfs_op_renew(struct nfs_cxn *cxn, struct curbuf *cur,
			    struct list_head *writes, struct rpc_write **wr)
{
	nfsstat4 status = NFS4_OK;
	clientid4 id;

	if (cur->len < 8) {
		status = NFS4ERR_BADXDR;
		goto out;
	}

	id = CR64();

	if (debugging)
		syslog(LOG_INFO, "op RENEW (CID:%Lx)",
			(unsigned long long) id);

	if (!clientid_touch(id))
		status = NFS4ERR_STALE_CLIENTID;

out:
	WR32(status);
	return status;
}

