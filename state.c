
#include <errno.h>
#include <syslog.h>
#include <glib.h>
#include "nfs4_prot.h"
#include "server.h"

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

static guint blob_hash_for_key(const struct blob *b)
{
	g_assert(b != NULL);
	g_assert(b->magic == BLOB_MAGIC);

	return blob_hash(BLOB_HASH_INIT, b->buf, b->len);
}

static gboolean blob_equal(const struct blob *a, const struct blob *b)
{
	g_assert(a != NULL);
	g_assert(a->magic == BLOB_MAGIC);
	g_assert(b != NULL);
	g_assert(b->magic == BLOB_MAGIC);

	if (a->len != b->len)
		return FALSE;
	if (memcmp(a->buf, b->buf, a->len))
		return FALSE;
	return TRUE;
}

static void nrand32(void *mem, unsigned int dwords)
{
	guint32 *v = mem;
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

nfsstat4 stateid_lookup(uint32_t id, struct nfs_state **st_out)
{
	struct nfs_state *st;

	st = g_hash_table_lookup(srv.state, GUINT_TO_POINTER(id));
	if (!st)
		return NFS4ERR_STALE_STATEID;

	if (st->flags & stfl_dead)
		return NFS4ERR_OLD_STATEID;

	*st_out = st;
	return NFS4_OK;
}

void state_trash(struct nfs_state *st)
{
	GList *last, *node;
	gboolean rc;

	st->flags |= stfl_dead;
	srv.dead_state = g_list_prepend(srv.dead_state, st);
	srv.n_dead++;

	if (srv.n_dead < SRV_STATE_HIGH_WAT)
		return;

	last = g_list_last(srv.dead_state);
	
	while (srv.n_dead > SRV_STATE_LOW_WAT) {
		node = last;
		last = last->prev;

		/* removing from hash table frees struct */
		st = node->data;
		rc = g_hash_table_remove(srv.state, GUINT_TO_POINTER(st->id));
		if (!rc) {
			syslog(LOG_ERR, "failed to GC state(ID:%u)", st->id);
			state_free(st);
		}

		srv.dead_state = g_list_delete_link(srv.dead_state, node);
		srv.n_dead--;
	}

	if (debugging)
		syslog(LOG_INFO, "state garbage collected");
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
	} while (g_hash_table_lookup(srv.clid_idx, id) != NULL);
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
	g_assert(clid != NULL);

	g_hash_table_remove(srv.client_ids, &clid->id);

	free(clid->id.buf);
	free_cb_client4(&clid->callback);
	free(clid);
}

void state_free(gpointer data)
{
	struct nfs_state *st = data;

	if (!st)
		return;

	if (st->owner)
		free(st->owner);
}

void client_free(gpointer data)
{
	struct nfs_client *cli = data;

	if (!cli)
		return;

	clientid_free(cli->id);

	if (cli->pending) {
		GList *tmp = cli->pending;
		while (tmp) {
			clientid_free(tmp->data);
			tmp = tmp->next;
		}
		g_list_free(cli->pending);
	}

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

guint short_clientid_hash(gconstpointer key)
{
	const clientid4 *clid = key;
	return *clid;
}

gboolean short_clientid_equal(gconstpointer _a, gconstpointer _b)
{
	const clientid4 *a = _a;
	const clientid4 *b = _b;
	return (*a == *b) ? TRUE : FALSE;
}

static int clientid_new(struct nfs_client *cli, struct nfs_cxn *cxn,
			SETCLIENTID4args *args, struct nfs_clientid **clid_out)
{
	struct nfs_clientid *clid;
	clientid4 *short_clid;

	clid = calloc(1, sizeof(struct nfs_clientid));
	if (!clid)
		goto err_out;

	/* copy client id */
	clid->id.magic = BLOB_MAGIC;
	clid->id.len = args->client.id.id_len;
	clid->id.buf = malloc(clid->id.len);
	if (!clid->id.buf)
		goto err_out_clid;
	memcpy(clid->id.buf, args->client.id.id_val, clid->id.len);

	/* copy client verifier */
	memcpy(&clid->cli_verf, &args->client.verifier, sizeof(verifier4));

	/* generate shorthand client id, random SETCLIENTID_CONFIRM verifier */
	gen_clientid4(&clid->id_short);
	rand_verifier(&clid->confirm_verf);

	/* copy callback info */
	if (copy_cb_client4(&clid->callback, &args->callback))
		goto err_out_clid_buf;
	clid->callback_ident = args->callback_ident;

	short_clid = malloc(sizeof(clientid4));
	if (!short_clid)
		goto err_out_cb_client4;
	memcpy(short_clid, &clid->id_short, sizeof(clientid4));

	/* add to short, long client id indices */
	g_hash_table_insert(srv.clid_idx, short_clid, cli);
	g_hash_table_insert(srv.client_ids, &clid->id, cli);

	*clid_out = clid;
	return 0;

err_out_cb_client4:
	free_cb_client4(&clid->callback);
err_out_clid_buf:
	free(clid->id.buf);
err_out_clid:
	free(clid);
err_out:
	return -ENOMEM;
}

static int client_new(struct nfs_cxn *cxn, SETCLIENTID4args *args,
		     struct nfs_clientid **clid_out)
{
	struct nfs_client *cli;
	struct nfs_clientid *clid = NULL;
	int rc = -ENOMEM;

	cli = calloc(1, sizeof(struct nfs_client));
	if (!cli)
		goto err_out;

	rc = clientid_new(cli, cxn, args, &clid);
	if (rc)
		goto err_out_st;

	/* add to state's client-id pending list */
	cli->pending = g_list_prepend(cli->pending, clid);

	*clid_out = clid;
	return 0;

err_out_st:
	free(cli);
err_out:
	return rc;
}

struct cancel_search {
	struct nfs_client	*cli;
	GList			*list;
};

static void cli_cancel_search(gpointer key, gpointer val, gpointer user_data)
{
	struct nfs_state *st = val;
	struct cancel_search *cs = user_data;

	if (st->cli == cs->cli)
		cs->list = g_list_append(cs->list, st);
}

static void client_cancel(struct nfs_cxn *cxn, struct nfs_client *cli)
{
	struct cancel_search cs = { cli };
	struct nfs_state *st;
	GList *tmp;

	if (debugging)
		syslog(LOG_INFO, "removing state associated with %Lx",
		       (cli && cli->id) ?
		       		(unsigned long long) cli->id->id_short : 0ULL);


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
}

static gboolean callback_equal(struct nfs_client *cli, cb_client4 *cb,
			       uint32_t cb_ident)
{
	struct nfs_clientid *clid;

	if (!cli)
		return FALSE;
	if (!cli->id)
		return FALSE;

	clid = cli->id;
	if (clid->callback_ident != cb_ident)
		return FALSE;
	if (clid->callback.cb_program != cb->cb_program)
		return FALSE;
	if (!cb->cb_location.r_addr || !cb->cb_location.r_netid)
		return FALSE;
	if (strcmp(clid->callback.cb_location.r_netid,
		   cb->cb_location.r_netid))
		return FALSE;
	if (strcmp(clid->callback.cb_location.r_addr,
		   cb->cb_location.r_addr))
		return FALSE;

	return TRUE;
}

bool_t nfs_op_setclientid(struct nfs_cxn *cxn, SETCLIENTID4args *args,
			  COMPOUND4res *cres)
{
	struct nfs_resop4 resop;
	SETCLIENTID4res *res;
	SETCLIENTID4resok *resok;
	nfsstat4 status = NFS4_OK;
	struct nfs_client *cli;
	int rc;
	struct nfs_clientid *clid = NULL;
	struct blob clid_key;

	if (debugging)
		syslog(LOG_INFO, "op SETCLIENTID (ID:%.*s "
		       "PROG:%u NET:%s ADDR:%s CBID:%u)",
		       args->client.id.id_len,
		       args->client.id.id_val,
		       args->callback.cb_program,
		       args->callback.cb_location.r_netid,
		       args->callback.cb_location.r_addr,
		       args->callback_ident);

	memset(&resop, 0, sizeof(resop));
	resop.resop = OP_SETCLIENTID;
	res = &resop.nfs_resop4_u.opsetclientid;
	resok = &res->SETCLIENTID4res_u.resok4;

	/* look up client id */
	clid_key.magic = BLOB_MAGIC;
	clid_key.len = args->client.id.id_len;
	clid_key.buf = args->client.id.id_val;
	cli = g_hash_table_lookup(srv.client_ids, &clid_key);

	if (!cli) {
		rc = client_new(cxn, args, &clid);
		if (rc < 0) {
			status = NFS4ERR_RESOURCE;
			goto out;
		}
	}

	else if ((!cli->id) ||
		 (memcmp(&cli->id->cli_verf, &args->client.verifier,
		 	 sizeof(verifier4))) ||
		 (!callback_equal(cli, &args->callback,
		 		  args->callback_ident))) {

		rc = clientid_new(cli, cxn, args, &clid);
		if (rc < 0) {
			status = NFS4ERR_RESOURCE;
			goto out;
		}

		/* add to state's client-id pending list */
		cli->pending = g_list_prepend(cli->pending, clid);
	}

	else {
		clid = cli->id;
	}

	g_assert(clid != NULL);

	resok->clientid = clid->id_short;
	memcpy(&resok->setclientid_confirm, &clid->confirm_verf,
	       sizeof(verifier4));

out:
	res->status = status;
	return push_resop(cres, &resop, status);
}

static gint compare_confirm(gconstpointer _a, gconstpointer _b)
{
	const struct nfs_clientid *a = _a;
	const struct nfs_clientid *b = _b;

	if ((a->id_short == b->id_short) &&
	    (!memcmp(&a->confirm_verf, &b->confirm_verf,
	    	     sizeof(verifier4))))
		return 0;

	return 1;
}

bool_t nfs_op_setclientid_confirm(struct nfs_cxn *cxn,
				  SETCLIENTID_CONFIRM4args *args,
				  COMPOUND4res *cres)
{
	struct nfs_resop4 resop;
	SETCLIENTID_CONFIRM4res *res;
	nfsstat4 status = NFS4_OK;
	struct nfs_client *cli;
	struct nfs_clientid *clid, *new_clid, clid_key;
	GList *tmp;

	if (debugging)
		syslog(LOG_INFO, "op SETCLIENTID_CONFIRM (ID:%Lx)",
		       (unsigned long long) args->clientid);

	memset(&resop, 0, sizeof(resop));
	resop.resop = OP_SETCLIENTID_CONFIRM;
	res = &resop.nfs_resop4_u.opsetclientid_confirm;

	/* get state record from clientid4 */
	cli = g_hash_table_lookup(srv.clid_idx, &args->clientid);
	if (!cli) {
		status = NFS4ERR_STALE_CLIENTID;
		goto out;
	}

	/* filter out duplicates */
	clid = cli->id;
	if (clid && (clid->id_short == args->clientid) &&
	    (!memcmp(&clid->confirm_verf, &args->setclientid_confirm,
	    	     sizeof(verifier4)))) {
		/* duplicate, just return success */
		goto out;
	}

	/*
	 * find the matching unconfirmed record (if any), and
	 * remove it from the unconfirmed list.
	 */
	clid_key.id_short = args->clientid;
	memcpy(&clid_key.confirm_verf, &args->setclientid_confirm,
		sizeof(verifier4));

	tmp = g_list_find_custom(cli->pending, &clid_key, compare_confirm);
	if (!tmp) {
		status = NFS4ERR_STALE_CLIENTID;
		goto out;
	}

	new_clid = tmp->data;
	cli->pending = g_list_delete_link(cli->pending, tmp);

	/*
	 * if old and new shorthand client ids are the same,
	 * we are just updating the callback
	 */
	if (clid && (clid->id_short == new_clid->id_short)) {
		/*
		 * FIXME: signal <not-yet-written code> to tear down
		 * the existing connection to the client
		 */

		goto out2;
	}

	/*
	 * if no pre-existing state exists, we are done
	 */
	if (!clid)
		goto out2;

	/*
	 * If we get this far, the client requires recovery.  Start
	 * the process of recovering locks, leases, etc.
	 */

	/* FIXME: probably need to do more than just forget state */
	client_cancel(cxn, cli);

out2:
	if (clid) {
		clientid4 *id_short = malloc(sizeof(clientid4));
		if (!id_short) {
			g_assert(new_clid != NULL);
			cli->pending = g_list_prepend(cli->pending, new_clid);
			status = NFS4ERR_RESOURCE;
			goto out;
		}
		memcpy(id_short, &clid->id_short, sizeof(clientid4));

		g_hash_table_replace(srv.clid_idx, id_short, NULL);
		clientid_free(clid);
	}
	cli->id = new_clid;
	g_hash_table_insert(srv.client_ids, &new_clid->id, cli);

out:
	res->status = status;
	return push_resop(cres, &resop, status);
}

