
#include <errno.h>
#include <syslog.h>
#include <glib.h>
#include "nfs4_prot.h"
#include "server.h"

/* "djb2"-derived hash function */
static unsigned long blob_hash(const void *_buf, size_t buflen)
{
	const unsigned char *buf = _buf;
	unsigned long hash = 5381UL;
	int c;

	while (buflen > 0) {
		c = *buf++;
		buflen--;

		hash = ((hash << 5) + hash) ^ c; /* hash * 33 ^ c */
	}

	return hash;
}

static guint blob_hash_for_key(const struct blob *b)
{
	return blob_hash(b->buf, b->len);
}

static gboolean blob_equal(const struct blob *a, const struct blob *b)
{
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

static void rand_verifier(verifier4 *verf)
{
	nrand32(verf, 5);
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

	dest->cb_location.r_netid = g_strdup(src->cb_location.r_netid);
	if (!dest->cb_location.r_netid)
		goto err_out;

	dest->cb_location.r_addr = g_strdup(src->cb_location.r_addr);
	if (!dest->cb_location.r_addr)
		goto err_out_1;

	return 0;

err_out_1:
	g_free(dest->cb_location.r_netid);
err_out:
	return rc;
}

static void free_cb_client4(cb_client4 *cbc)
{
	g_free(cbc->cb_location.r_netid);
	g_free(cbc->cb_location.r_addr);
}

static void clientid_free(struct nfs_clientid *id)
{
	if (!id)
		return;
	
	g_free(id->id.buf);
	free_cb_client4(&id->callback);
	g_slice_free(struct nfs_clientid, id);
}

void state_free(gpointer data)
{
	struct nfs_state *st = data;

	clientid_free(st->id);

	if (st->pending) {
		GList *tmp = st->pending;
		while (tmp) {
			clientid_free(tmp->data);
			tmp = tmp->next;
		}
		g_list_free(st->pending);
	}

	g_slice_free(struct nfs_state, st);
}

guint clientid_hash(gconstpointer key)
{
	const struct nfs_clientid *clid = key;
	return blob_hash_for_key(&clid->id);
}

gboolean clientid_equal(gconstpointer _a, gconstpointer _b)
{
	const struct nfs_clientid *a = _a;
	const struct nfs_clientid *b = _b;
	return blob_equal(&a->id, &b->id);
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

static int clientid_new(struct nfs_state *st, struct nfs_client *cli,
			SETCLIENTID4args *args, struct nfs_clientid **clid_out)
{
	struct nfs_clientid *clid;
	clientid4 *short_clid;

	clid = g_slice_new0(struct nfs_clientid);
	if (!clid)
		goto err_out;

	/* copy client id */
	clid->id.len = args->client.id.id_len;
	clid->id.buf = g_memdup(args->client.id.id_val, clid->id.len);
	if (!clid->id.buf)
		goto err_out_clid;

	/* copy client verifier */
	memcpy(&clid->cli_verf, &args->client.verifier, sizeof(verifier4));

	/* generate shorthand client id, random SETCLIENTID_CONFIRM verifier */
	gen_clientid4(&clid->id_short);
	rand_verifier(&clid->confirm_verf);

	/* copy callback info */
	if (copy_cb_client4(&clid->callback, &args->callback))
		goto err_out_clid_buf;
	clid->callback_ident = args->callback_ident;

	short_clid = g_memdup(&clid->id_short, sizeof(clientid4));
	if (!short_clid)
		goto err_out_cb_client4;

	g_hash_table_insert(srv.clid_idx, short_clid, st);

	*clid_out = clid;
	return 0;

err_out_cb_client4:
	free_cb_client4(&clid->callback);
err_out_clid_buf:
	g_free(clid->id.buf);
err_out_clid:
	g_slice_free(struct nfs_clientid, clid);
err_out:
	return -ENOMEM;
}

static int state_new(struct nfs_client *cli, SETCLIENTID4args *args,
		     struct nfs_clientid **clid_out)
{
	struct nfs_state *st;
	struct nfs_clientid *clid = NULL;
	int rc = -ENOMEM;

	st = g_slice_new0(struct nfs_state);
	if (!st)
		goto err_out;

	rc = clientid_new(st, cli, args, &clid);
	if (rc)
		goto err_out_st;
	
	/* add to state's client-id pending list */
	st->pending = g_list_prepend(st->pending, clid);

	/* add to global list of client ids */
	g_hash_table_insert(srv.client_ids, clid, st);

	*clid_out = clid;
	return 0;

err_out_st:
	g_slice_free(struct nfs_state, st);
err_out:
	return rc;
}

static gboolean callback_equal(struct nfs_state *st, cb_client4 *cb,
			       uint32_t cb_ident)
{
	struct nfs_clientid *clid;

	if (!st)
		return FALSE;
	if (!st->id)
		return FALSE;

	clid = st->id;
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

bool_t nfs_op_setclientid(struct nfs_client *cli, SETCLIENTID4args *args,
			  COMPOUND4res *cres)
{
	struct nfs_resop4 resop;
	SETCLIENTID4res *res;
	SETCLIENTID4resok *resok;
	nfsstat4 status = NFS4_OK;
	struct nfs_state *st;
	int rc;
	struct nfs_clientid *clid = NULL, clid_key;

	memset(&resop, 0, sizeof(resop));
	resop.resop = OP_SETCLIENTID;
	res = &resop.nfs_resop4_u.opsetclientid;
	resok = &res->SETCLIENTID4res_u.resok4;

	/* look up client id */
	memset(&clid_key, 0, sizeof(clid_key));
	clid_key.id.len = args->client.id.id_len;
	clid_key.id.buf = args->client.id.id_val;
	st = g_hash_table_lookup(srv.client_ids, &clid_key);

	if (!st) {
		rc = state_new(cli, args, &clid);
		if (rc < 0) {
			status = NFS4ERR_RESOURCE;
			goto out;
		}
	}

	else if ((!st->id) ||
		 (memcmp(&st->id->cli_verf, &args->client.verifier,
		 	 sizeof(verifier4))) ||
		 (!callback_equal(st, &args->callback,
		 		  args->callback_ident))) {

		rc = clientid_new(st, cli, args, &clid);
		if (rc < 0) {
			status = NFS4ERR_RESOURCE;
			goto out;
		}

		/* add to state's client-id pending list */
		st->pending = g_list_prepend(st->pending, clid);
	}

	else {
		clid = st->id;
	}

	g_assert(clid != NULL);

	resok->clientid = clid->id_short;
	memcpy(&resok->setclientid_confirm, &clid->confirm_verf,
	       sizeof(verifier4));

out:
	res->status = status;
	return push_resop(cres, &resop, status);
}

bool_t nfs_op_setclientid_confirm(struct nfs_client *cli,
				  SETCLIENTID_CONFIRM4args *arg,
				  COMPOUND4res *cres)
{
	struct nfs_resop4 resop;
	SETCLIENTID_CONFIRM4res *res;
#if 0
	nfsstat4 status = NFS4_OK;
#else
	nfsstat4 status = NFS4ERR_NOTSUPP;
#endif

	memset(&resop, 0, sizeof(resop));
	resop.resop = OP_SETCLIENTID_CONFIRM;
	res = &resop.nfs_resop4_u.opsetclientid_confirm;

	/* FIXME */

#if 0
out:
#endif
	res->status = status;
	return push_resop(cres, &resop, status);
}
