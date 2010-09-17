
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
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include <event.h>
#include <glib.h>
#include "nfs4_prot.h"
#include "server.h"
#include "elist.h"

struct nfs_clientid {
	struct blob		id;		/* client-supplied opaque id */
	clientid4		id_short;	/* shorthand id */

	verifier4		cli_verf;	/* client-supplied verifier */
	verifier4		confirm_verf;	/* clientid confirm verifier */

	cb_client4		callback;
	uint32_t		callback_ident;

	struct cxn_auth		auth;

	bool			expired;

	bool			pending;
	struct list_head	node;

	struct list_head	owner_list;

	struct event		timer;
};

static LIST_HEAD(cli_unconfirmed);
LIST_HEAD(ino_openfile_list);

static void client_cancel_id(struct nfs_clientid *, bool);
static nfsstat4 clientid_touch(clientid4 id_in);

static bool blob_equal(const struct blob *a, const struct blob *b)
{
	if (a == b)
		return true;
	if (!a || !b || a->len != b->len)
		return false;
	return memcmp(a->buf, b->buf, a->len) == 0 ? true : false;
}

void rand_verifier(verifier4 *verf)
{
	nrand32(verf, 2);
}

static bool auth_equal(const struct cxn_auth *a, const struct cxn_auth *b)
{
	if (a->type != b->type)
		return false;
	if (strcmp(a->host, b->host))
		return false;

	switch (a->type) {
	case auth_none:
		/* do nothing */
		break;

	case auth_unix:
		if ((a->u.up.uid != b->u.up.uid) ||
		    (a->u.up.gid != b->u.up.gid))
			return false;
		break;
	}

	return true;
}

uint32_t gen_stateid(void)
{
	int loop = 1000000;
	uint32_t tmp = 0;

	do {
		if (G_UNLIKELY(loop == 0)) {
			applog(LOG_ERR, "gen_stateid: 1,000,000 collisions");
			return 0;
		}

		loop--;

		nrand32(&tmp, 1);
	} while (g_hash_table_lookup(srv.openfiles, GUINT_TO_POINTER(tmp)) != NULL);

	return tmp;
}

static bool stateid_bad(const struct nfs_stateid *sid)
{
	if (memcmp(&sid->server_magic, SRV_MAGIC, 4))
		return true;
	return false;
}

static bool stateid_stale(const struct nfs_stateid *sid)
{
	if (memcmp(&sid->server_verf, &srv.instance_verf, 4))
		return true;
	return false;
}

nfsstat4 owner_lookup_name(clientid4 id, struct nfs_buf *owner,
			   struct nfs_owner **owner_out)
{
	struct nfs_owner *o;
	struct nfs_clientid *clid;

	*owner_out = NULL;

	clid = g_hash_table_lookup(srv.clid_idx, (void *)(unsigned long) id);
	if (!clid)
		return NFS4ERR_STALE_CLIENTID;

	list_for_each_entry(o, &clid->owner_list, cli_node) {
		size_t len;

		len = strlen(o->owner);
		if ((len == owner->len) &&
		    !memcmp(owner->val, o->owner, len)) {
			*owner_out = o;
			return NFS4_OK;
		}
	}

	return NFS4_OK;
}

nfsstat4 openfile_lookup_owner(struct nfs_owner *o,
			 struct nfs_inode *ino,
			 struct nfs_openfile **of_out)
{
	struct nfs_openfile *of;

	*of_out = NULL;

	list_for_each_entry(of, &ino_openfile_list, inode_node) {
		if (of->inum == ino->inum &&
		    of->type == nst_open &&
		    of->owner == o) {
			*of_out = of;
			break;
		}
	}

	return NFS4_OK;
}

nfsstat4 openfile_lookup(struct nfs_stateid *id_in,
			 struct nfs_inode *ino,
			 enum nfs_state_type type,
			 struct nfs_openfile **of_out)
{
	struct nfs_openfile *of;

	*of_out = NULL;

	if (stateid_bad(id_in))
		return NFS4ERR_BAD_STATEID;
	if (stateid_stale(id_in))
		return NFS4ERR_STALE_STATEID;

	of = g_hash_table_lookup(srv.openfiles, GUINT_TO_POINTER(id_in->id));
	if (!of)
		return NFS4ERR_STALE_STATEID;

	if (of->type == nst_dead) {
		if (type != nst_dead) {
			if (of->flags & nsf_expired)
				return NFS4ERR_EXPIRED;
			return NFS4ERR_OLD_STATEID;
		}
	} else {
		g_assert(of->owner != NULL);

		if ((type != nst_any) && (of->type != type))
			return NFS4ERR_BAD_STATEID;

		if (id_in->seqid != of->my_seq)
			return NFS4ERR_OLD_STATEID;

		if (ino && (ino->inum != of->inum))
			return NFS4ERR_BAD_STATEID;

		clientid_touch(of->owner->cli);
	}

	*of_out = of;

	return NFS4_OK;
}

static bool state_self(const struct nfs_access *ac, const struct nfs_openfile *of)
{
	if (of == ac->self)
		return true;

	if ((of->type == nst_open) && (ac->clientid == of->owner->cli) &&
	    ac->owner && ac->owner->len &&
	    (strlen(of->owner->owner) == ac->owner->len) &&
	    (!memcmp(of->owner, ac->owner->val, ac->owner->len)))
		return true;

	return false;
}

struct state_search_info {
	bool			opens;
	bool			locks;

	nfsstat4		status;
};

static void access_search(struct nfs_access *ac, struct state_search_info *ssi,
			  struct nfs_openfile *of)
{
	switch (of->type) {

	case nst_open: {
		if (!ssi->opens)
			return;

		if ((of->share_deny & ac->share_access) &&
		    ((ac->op == OP_OPEN) || !state_self(ac, of))) {
			ac->match = of;
			if ((ac->op == OP_WRITE) || (ac->op == OP_READ))
				ssi->status = NFS4ERR_LOCKED;
			else
				ssi->status = NFS4ERR_SHARE_DENIED;

		} else if (of->share_access & ac->share_deny) {
			ac->match = of;
			ssi->status = NFS4ERR_SHARE_DENIED;

		} else if (state_self(ac, of) &&
			 !(of->share_access & ac->share_access)) {
			ac->match = of;
			ssi->status = NFS4ERR_OPENMODE;
		}
		break;
	}

	case nst_lock: {
		struct nfs_lock *lock;
		uint64_t ssi_end_ofs, end_ofs;

		if (!ssi->locks)
			return;

		if (ac->len == 0xffffffffffffffffULL)
			ssi_end_ofs = 0xffffffffffffffffULL;
		else
			ssi_end_ofs = ac->ofs + ac->len;

		list_for_each_entry(lock, &of->lock_list, node) {
			if (lock->len == 0xffffffffffffffffULL)
				end_ofs = 0xffffffffffffffffULL;
			else
				end_ofs = lock->ofs + lock->len;

			if (ssi_end_ofs <= lock->ofs)
				continue;
			if (end_ofs <= ac->ofs)
				continue;
			if (((lock->type == READ_LT) ||
			     (lock->type == READW_LT)) &&
			    ((ac->locktype == READ_LT) ||
			     (ac->locktype == READW_LT)))
				continue;

			ac->match = of;
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

nfsstat4 access_ok(struct nfs_access *ac)
{
	struct state_search_info ssi;
	struct nfs_openfile *tmp_of;

	ac->self = NULL;
	ac->match = NULL;

	if (ac->sid && (ac->sid->seqid != 0) &&
	    (ac->sid->seqid != 0xffffffffU)) {
		nfsstat4 status = openfile_lookup(ac->sid, ac->ino,
						 nst_any, &ac->self);
		if (status != NFS4_OK)
			return status;
	}

	ssi.opens = false;
	ssi.locks = false;

	switch (ac->op) {
	case OP_OPEN:
		ssi.opens = true;
		break;
	case OP_LOCK:
	case OP_LOCKT:
		ssi.locks = true;
		break;
	case OP_WRITE:
	case OP_SETATTR:
		ac->share_access = OPEN4_SHARE_ACCESS_WRITE;
		ssi.opens = true;
		break;
	case OP_READ:
		ac->share_access = OPEN4_SHARE_ACCESS_READ;
		ssi.opens = true;
		break;
	default:
		ssi.opens = true;
		ssi.locks = true;
		break;
	}

	ssi.status = NFS4_OK;

	list_for_each_entry(tmp_of, &ino_openfile_list, inode_node) {
		if (tmp_of->inum == ac->ino->inum)
			access_search(ac, &ssi, tmp_of);
	}

	return ssi.status;
}

static void openfile_trash_locks(struct nfs_openfile *of)
{
	struct nfs_lock *tmp, *iter;

	list_for_each_entry_safe(tmp, iter, &of->lock_list, node) {
		list_del(&tmp->node);

		memset(tmp, 0, sizeof(*tmp));
		free(tmp);
	}
}

void openfile_free(gpointer data)
{
	struct nfs_openfile *of = data;

	if (!of)
		return;

	srv.stats.openfile_free++;

	switch (of->type) {
	case nst_any:
		/* invalid type, should never happen */
		/* fall through */

	case nst_open:
	case nst_lock:
		/* do nothing */
		break;
	case nst_dead:
		list_del_init(&of->death_node);
		break;
	}

	openfile_trash_locks(of);

	if (of->inum) {
		list_del_init(&of->inode_node);
		of->inum = 0;
	}

	if (of->owner) {
		list_del_init(&of->owner_node);
		of->owner = NULL;
	}

	memset(of, 0, sizeof(*of));
	free(of);
}

void state_gc(void)
{
	struct nfs_openfile *of, *iter;

	list_for_each_entry_safe(of, iter, &srv.dead, death_node) {
		if (of->death_time > current_time.tv_sec)
			break;

		g_hash_table_remove(srv.openfiles, GUINT_TO_POINTER(of->id));
	}
}

void openfile_trash(struct nfs_openfile *of, bool expired)
{
	if (of->type == nst_dead)
		return;

	if (of->type == nst_lock)
		openfile_trash_locks(of);

	if (of->inum) {
		struct nfs_inode *ino = inode_getdec(NULL, of->inum, 0);

		of->inum = 0;

		list_del_init(&of->inode_node);

		if (ino && of->type == nst_open) {
			struct nfs_openfile *tmp_of, *iter;

			list_for_each_entry_safe(tmp_of, iter,
						 &ino_openfile_list,
						 inode_node) {
				if (tmp_of->inum == ino->inum &&
				    tmp_of->type == nst_lock &&
				    tmp_of->lock_open == of)
					openfile_trash(tmp_of, expired);
			}
		}

		inode_free(ino);
	}

	if (of->owner) {
		list_del_init(&of->owner_node);
		of->owner = NULL;
	}

	of->type = nst_dead;
	if (expired)
		of->flags |= nsf_expired;
	of->death_time = current_time.tv_sec + SRV_STATE_DEATH;
	list_add_tail(&of->death_node, &srv.dead);
}

void owner_free(struct nfs_owner *o)
{
	if (!o)
		return;

	/* FIXME technically we should loop through o->openfiles
	 * and free resources, but I /think/ all paths already
	 * do that for us
	 */
	if (!list_empty(&o->openfiles))
		applog(LOG_WARNING,
		       "owner_free openfile list not empty (%s)",
		       o->owner ? o->owner : "\"\"");

	free(o->owner);

	memset(o, 0, sizeof(*o));
	free(o);
}

struct nfs_owner *owner_new(enum nfs_state_type type, struct nfs_buf *owner)
{
	struct nfs_owner *o;

	o = calloc(1, sizeof(struct nfs_owner));
	if (!o)
		return NULL;

	o->owner = g_strndup(owner->val, owner->len);
	if (!o->owner) {
		free(o);
		return NULL;
	}

	o->type = type;

	INIT_LIST_HEAD(&o->openfiles);
	INIT_LIST_HEAD(&o->cli_node);

	return o;
}

struct nfs_openfile *openfile_new(enum nfs_state_type type, struct nfs_owner *o)
{
	struct nfs_openfile *of;

	if (!o)
		return NULL;
	if ((type != nst_open) && (type != nst_lock))
		return NULL;

	srv.stats.openfile_alloc++;

	of = calloc(1, sizeof(*of));
	if (!of)
		return NULL;

	of->owner = o;
	of->type = type;
	of->my_seq = random() & 0xfff;
	of->id = gen_stateid();
	if (!of->id) {
		free(of);
		return NULL;
	}

	INIT_LIST_HEAD(&of->lock_list);
	INIT_LIST_HEAD(&of->inode_node);
	INIT_LIST_HEAD(&of->owner_node);
	INIT_LIST_HEAD(&of->death_node);

	return of;
}

static void gen_clientid4(clientid4 *id)
{
	int loop = 1000000;

	do {
		if (G_UNLIKELY(loop == 0)) {
			applog(LOG_ERR, "gen_clientid: 1,000,000 collisions");
			*id = 0;
			return;
		}

		loop--;

		nrand32(id, 2);
	} while (g_hash_table_lookup(srv.clid_idx,
				(void *)((unsigned long) *id)) != NULL);
}

static int evtimer_renew(struct event *ev, int more_sec)
{
	struct timeval tv;

	evtimer_del(ev);

	tv.tv_sec = more_sec;
	tv.tv_usec = 0;

	return evtimer_add(ev, &tv);
}

static nfsstat4 clientid_touch(clientid4 id_in)
{
	struct nfs_clientid *clid;
	unsigned long id = (unsigned long) id_in;

	clid = g_hash_table_lookup(srv.clid_idx, (void *) id);
	if (!clid)
		return NFS4ERR_STALE_CLIENTID;
	if (clid->expired)
		return NFS4ERR_EXPIRED;

	evtimer_renew(&clid->timer, SRV_LEASE_TIME);

	return NFS4_OK;
}

nfsstat4 clientid_test(clientid4 id_in)
{
	struct nfs_clientid *clid;
	unsigned long id = (unsigned long) id_in;

	clid = g_hash_table_lookup(srv.clid_idx, (void *) id);
	if (!clid)
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
	struct nfs_owner *o, *iter;

	srv.stats.clid_free++;

	if (!clid)
		return;

	if (clid->pending)
		list_del(&clid->node);
	else
		evtimer_del(&clid->timer);

	g_hash_table_remove(srv.clid_idx,
			    (void *)(unsigned long) clid->id_short);

	free(clid->id.buf);
	free_cb_client4(&clid->callback);

	list_for_each_entry_safe(o, iter, &clid->owner_list, cli_node) {
		list_del(&o->cli_node);
		owner_free(o);
	}

	memset(clid, 0, sizeof(*clid));
	free(clid);
}

static void clientid_timer(int fd, short events, void *userdata)
{
	struct nfs_clientid *clid = userdata;
	const char *msg;
	unsigned long long id_short;

	id_short = clid->id_short;

	/* if pending, or already cancelled this client's state
	 * via lease expiration, then just free the record
	 */
	if (clid->pending) {
		clientid_free(clid);
		msg = "released unconfirmed";
	} else if (clid->expired) {
		clientid_free(clid);
		msg = "released";
	} else {
		client_cancel_id(clid, true);

		/* after cancelling state via lease expiration,
		 * keep the client id around for a while longer
		 */
		clid->expired = true;
		evtimer_renew(&clid->timer, SRV_CLID_DEATH);

		msg = "expired state for";
	}

	if (debugging)
		applog(LOG_INFO, "timeout, %s CID:%Lx", msg, id_short);
}

static int clientid_new(struct nfs_cxn *cxn,
			struct nfs_buf *id_long, verifier4 *client_verf,
			uint32_t cb_ident, const cb_client4 *callback,
			struct nfs_clientid **clid_out)
{
	struct nfs_clientid *clid;
	unsigned long short_clid;

	srv.stats.clid_alloc++;

	clid = calloc(1, sizeof(struct nfs_clientid));
	if (!clid)
		goto err_out;

	INIT_LIST_HEAD(&clid->owner_list);
	INIT_LIST_HEAD(&clid->node);
	evtimer_set(&clid->timer, clientid_timer, clid);

	memcpy(&clid->auth, &cxn->auth, sizeof(struct cxn_auth));

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
	/* FIXME: 1-in-a-billion chance of picking an existing,
	 * unconfirmed id
	 */
	gen_clientid4(&clid->id_short);
	rand_verifier(&clid->confirm_verf);

	/* copy callback info */
	if (copy_cb_client4(&clid->callback, callback))
		goto err_out_clid_buf;
	clid->callback_ident = cb_ident;

	short_clid = (unsigned long) clid->id_short;

	*clid_out = clid;
	return 0;

err_out_clid_buf:
	free(clid->id.buf);
err_out_clid:
	free(clid);
err_out:
	return -ENOMEM;
}

static void client_cancel_id(struct nfs_clientid *clid, bool expired)
{
	struct nfs_owner *owner;
	struct nfs_openfile *of, *iter;
	unsigned int trashed = 0;

	list_for_each_entry(owner, &clid->owner_list, cli_node) {
		list_for_each_entry_safe(of, iter, &owner->openfiles,
					 owner_node) {
			if (of->type == nst_open) {
				openfile_trash(of, expired);
				trashed++;
			}
		}
	}

	if (debugging)
		applog(LOG_INFO,
		       "%s %u openfile recs associated with CID:%Lx",
		       expired ? "expired" : "cancelled",
		       trashed, (unsigned long long) clid->id_short);
}

struct client_cancel_info {
	const struct blob	*key;
	GList			*list;
};

static void client_cancel_iter(gpointer key, gpointer val, gpointer user_data)
{
	struct nfs_clientid *clid = val;
	struct client_cancel_info *cci = user_data;

	if (blob_equal(cci->key, &clid->id))
		cci->list = g_list_prepend(cci->list, clid);
}

static void client_cancel(const struct blob *key)
{
	struct client_cancel_info cci = { key, NULL };
	GList *tmp;

	g_hash_table_foreach(srv.clid_idx, client_cancel_iter, &cci);

	tmp = cci.list;
	while (tmp) {
		struct nfs_clientid *clid;

		clid = tmp->data;
		client_cancel_id(clid, false);

		tmp = tmp->next;
	}

	g_list_free(cci.list);
}

void cli_owner_add(struct nfs_owner *owner)
{
	struct nfs_clientid *clid;

	clid = g_hash_table_lookup(srv.clid_idx,
				   (void *)(unsigned long) owner->cli);
	/* FIXME: handle NULL */

	list_add(&owner->cli_node, &clid->owner_list);
}

static void cli_clear_pending(const struct blob *key)
{
	struct nfs_clientid *clid, *iter;
	unsigned int cleared = 0;

	list_for_each_entry_safe(clid, iter, &cli_unconfirmed, node) {
		if (blob_equal(key, &clid->id)) {
			clientid_free(clid);
			cleared++;
		}
	}

	if (debugging && cleared)
		applog(LOG_DEBUG, "cleared %u unconfirmed entries", cleared);
}

static void clientid_promote(struct nfs_clientid *old_clid,
			     struct nfs_clientid *new_clid)
{
	unsigned long id_short;

	if (old_clid) {
		list_splice_init(&old_clid->owner_list, &new_clid->owner_list);

		id_short = (unsigned long) old_clid->id_short;
		g_hash_table_remove(srv.clid_idx, (void *) id_short);
		clientid_free(old_clid);
	}

	new_clid->pending = false;
	list_del(&new_clid->node);

	evtimer_renew(&new_clid->timer, SRV_LEASE_TIME);

	id_short = (unsigned long) new_clid->id_short;
	g_hash_table_insert(srv.clid_idx, (void *) id_short, new_clid);
}

struct client_search_info {
	struct blob		key;
	struct nfs_clientid	*result;
};

static void client_search_iter(gpointer key, gpointer val, gpointer user_data)
{
	struct nfs_clientid *clid = val;
	struct client_search_info *csi = user_data;

	if (blob_equal(&csi->key, &clid->id))
		csi->result = clid;
}

nfsstat4 nfs_op_setclientid(struct nfs_cxn *cxn, struct curbuf *cur,
			    struct list_head *writes, struct rpc_write **wr)
{
	nfsstat4 status = NFS4_OK;
	int rc;
	struct nfs_clientid *clid = NULL;
	struct nfs_buf client, tmpstr;
	verifier4 *client_verf;
	uint32_t cb_ident;
	cb_client4 callback;
	struct client_search_info csi;
	struct nfs_clientid *confirmed;

	cxn->drc_mask |= drc_setcid;

	client_verf = CURMEM(sizeof(verifier4));
	CURBUF(&client);

	memset(&callback, 0, sizeof(callback));

	callback.cb_program = CR32();	/* cb_program */
	CURBUF(&tmpstr);		/* r_netid */
	if (tmpstr.len)
		callback.cb_location.r_netid = g_strndup(tmpstr.val, tmpstr.len);
	CURBUF(&tmpstr);		/* r_addr */
	if (tmpstr.len)
		callback.cb_location.r_addr = g_strndup(tmpstr.val, tmpstr.len);
	cb_ident = CR32();		/* callback_ident */

	/* look up client id */
	csi.key.magic = BLOB_MAGIC;
	csi.key.len = client.len;
	csi.key.buf = client.val;
	csi.result = NULL;
	g_hash_table_foreach(srv.clid_idx, client_search_iter, &csi);
	confirmed = csi.result;

	/* if client id seen, verify it matches recorded principal */
	if (confirmed && !auth_equal(&cxn->auth, &confirmed->auth)) {
		status = NFS4ERR_CLID_INUSE;
		goto out;
	}

	/* clear unconfirmed entries matching this client id */
	cli_clear_pending(&csi.key);

	/* create new unconfirmed record */
	rc = clientid_new(cxn, &client, client_verf,
			  cb_ident, &callback, &clid);
	if (rc < 0) {
		status = NFS4ERR_RESOURCE;
		goto out;
	}

	/* just a callback update? */
	if (confirmed &&
	    !memcmp(&confirmed->cli_verf, client_verf, sizeof(verifier4)))
		clid->id_short = confirmed->id_short;

	/* add to global unconfirmed list */
	clid->pending = true;
	list_add(&clid->node, &cli_unconfirmed);

out:
	if (debugging) {
		uint64_t u;

		memcpy(&u, client_verf, 8);
		applog(LOG_INFO, "op SETCLIENTID (ID:%.*s "
		       "VERF:%Lx)",
		       client.len,
		       client.val,
		       (unsigned long long) u);
		applog(LOG_INFO, "   SETCLIENTID ("
		       "PROG:%u NET:%s ADDR:%s CBID:%u)",
		       callback.cb_program,
		       callback.cb_location.r_netid,
		       callback.cb_location.r_addr,
		       cb_ident);
	}

	WR32(status);
	if (status == NFS4_OK) {
		g_assert(clid != NULL);

		WR64(clid->id_short);
		WRMEM(&clid->confirm_verf, sizeof(verifier4));

		if (debugging) {
			uint64_t u;

			memcpy(&u, &clid->confirm_verf, 8);
			applog(LOG_INFO, "   SETCLIENTID -> (CLID:%Lx "
				"VERF:%Lx)",
				(unsigned long long) clid->id_short,
				(unsigned long long) u);
		}
	}
	else if (status == NFS4ERR_CLID_INUSE) {
		WRSTR(confirmed->callback.cb_location.r_netid);
		WRSTR(confirmed->callback.cb_location.r_addr);
	}

	free(callback.cb_location.r_netid);
	free(callback.cb_location.r_addr);
	return status;
}

nfsstat4 nfs_op_setclientid_confirm(struct nfs_cxn *cxn, struct curbuf *cur,
			    struct list_head *writes, struct rpc_write **wr)
{
	nfsstat4 status = NFS4_OK;
	struct nfs_clientid *new_clid, *tmp_clid, *confirmed;
	verifier4 *confirm_verf;
	clientid4 id_short;

	cxn->drc_mask |= drc_setcidconf;

	id_short = CR64();
	confirm_verf = CURMEM(sizeof(verifier4));

	if (debugging) {
		uint64_t u;

		memcpy(&u, confirm_verf, 8);
		applog(LOG_INFO, "op SETCLIENTID_CONFIRM (ID:%Lx VERF:%Lx)",
		       (unsigned long long) id_short,
		       (unsigned long long) u);
	}

	/* find the matching confirmed record (if any) */
	confirmed = g_hash_table_lookup(srv.clid_idx,
					(void *)(unsigned long) id_short);
	if (confirmed && !auth_equal(&confirmed->auth, &cxn->auth)) {
		status = NFS4ERR_CLID_INUSE;
		goto out;
	}

	/*
	 * find the matching unconfirmed record (if any)
	 */
	new_clid = NULL;
	list_for_each_entry(tmp_clid, &cli_unconfirmed, node) {
		if ((tmp_clid->id_short == id_short) &&
		    !memcmp(&tmp_clid->confirm_verf, confirm_verf,
		    	    sizeof(verifier4))) {
			new_clid = tmp_clid;
			break;
		}
	}
	if (new_clid && !auth_equal(&new_clid->auth, &cxn->auth)) {
		status = NFS4ERR_CLID_INUSE;
		goto out;
	}

	/*
	 * Tests, in the order presented by RFC 3530
	 */

	/* check for callback update */
	if (confirmed && new_clid &&
	    !memcmp(&confirmed->cli_verf, &new_clid->cli_verf,
		    sizeof(verifier4)) &&
	    memcmp(&confirmed->confirm_verf, confirm_verf, sizeof(verifier4))) {
		/*
		 * FIXME: signal <not-yet-written code> to tear down
		 * the existing connection to the client
		 */
		clientid_promote(confirmed, new_clid);

		if (debugging)
			applog(LOG_INFO, "   SETCLIENTID_CONFIRM -> cb update");
		goto out;
	}

	/* check for replay that DRC missed */
	else if (confirmed && !new_clid) {
		if (debugging)
			applog(LOG_INFO, "   SETCLIENTID_CONFIRM -> replay");
		goto out;
	}

	/* confirm the record. */
	else if (!confirmed && new_clid) {
		client_cancel(&new_clid->id);		/* remove state */
		clientid_promote(NULL, new_clid);
		if (debugging)
			applog(LOG_INFO, "   SETCLIENTID_CONFIRM -> confirm");
	}

	else {
		status = NFS4ERR_STALE_CLIENTID;
		goto out;
	}

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
		applog(LOG_INFO, "op RENEW (CID:%Lx)",
			(unsigned long long) id);

	status = clientid_touch(id);

out:
	WR32(status);
	return status;
}

