
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

static nfsstat4 clientid_touch(clientid4 id_in);

void rand_verifier(verifier4 *verf)
{
	nrand32(verf, 2);
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

	clid = g_hash_table_lookup(srv.clid_idx, &id);
	if (!clid) {
		if (debugging)
			applog(LOG_INFO, "clientid %016llx not in clid_idx",
				(unsigned long long) id);
		return NFS4ERR_STALE_CLIENTID;
	}

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

#if 0
		if (id_in->seqid != of->my_seq)
			return NFS4ERR_OLD_STATEID;
#endif


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

static int evtimer_renew(struct event *ev, int more_sec)
{
	struct timeval tv;

	evtimer_del(ev);

	tv.tv_sec = more_sec;
	tv.tv_usec = 0;

	return evtimer_add(ev, &tv);
}

static struct nfs_clientid *clientid_new(void)
{
	struct nfs_clientid *clid;

	clid = calloc(1, sizeof(*clid));
	if (!clid)
		return NULL;

	INIT_LIST_HEAD(&clid->node);
	INIT_LIST_HEAD(&clid->owner_list);

	return clid;
}

guint clientid_hash(gconstpointer key_p)
{
	const fsdb_client_id *key = key_p;

	return (guint) (uint64_t) (*key);
}

gboolean clientid_equal(gconstpointer a_p, gconstpointer b_p)
{
	const fsdb_client_id *a = a_p;
	const fsdb_client_id *b = b_p;

	return (*a == *b) ? TRUE : FALSE;
}

static nfsstat4 clientid_touch(clientid4 id)
{
	struct nfs_clientid *clid;

	clid = g_hash_table_lookup(srv.clid_idx, &id);
	if (!clid)
		return NFS4ERR_STALE_CLIENTID;
	if (clid->expired)
		return NFS4ERR_EXPIRED;

	evtimer_renew(&clid->timer, SRV_LEASE_TIME);

	return NFS4_OK;
}

nfsstat4 clientid_test(clientid4 id)
{
	struct nfs_clientid *clid;

	clid = g_hash_table_lookup(srv.clid_idx, &id);
	if (!clid)
		return NFS4ERR_STALE_CLIENTID;
	return NFS4_OK;
}

struct client_cancel_info {
	const struct blob	*key;
	GList			*list;
};

void cli_owner_add(struct nfs_owner *owner)
{
	struct nfs_clientid *clid;

	clid = g_hash_table_lookup(srv.clid_idx, &owner->cli);
	/* FIXME: handle NULL */

	list_add(&owner->cli_node, &clid->owner_list);
}

nfsstat4 nfs_op_exchange_id(struct nfs_cxn *cxn, const EXCHANGE_ID4args *args,
			     struct list_head *writes, struct rpc_write **wr)
{
	uint32_t *status_p;
	nfsstat4 status = NFS4_OK;
	fsdb_client cli = {};
	bool ok_commit = false;
	DB_TXN *txn = NULL;
	DB_ENV *dbenv = srv.fsdb.env;

	if (debugging)
		applog(LOG_INFO, "op EXCHANGE_ID (%.*s, %x)",
			args->eia_clientowner.co_ownerid.co_ownerid_len,
			args->eia_clientowner.co_ownerid.co_ownerid_val,
			args->eia_flags);

	status_p = WRSKIP(4);			/* ending status */

	/* we only support SP4_NONE */
	if (args->eia_state_protect.spa_how != SP4_NONE) {
		status = NFS4ERR_NOTSUPP;
		goto out;
	}

	/* EXCHGID4_FLAG_CONFIRMED_R prohibited in eia_flags */
	if (args->eia_flags & EXCHGID4_FLAG_CONFIRMED_R) {
		status = NFS4ERR_INVAL;
		goto out;
	}

	int rc = dbenv->txn_begin(dbenv, NULL, &txn, 0);
	if (rc) {
		status = NFS4ERR_IO;
		dbenv->err(dbenv, rc, "DB_ENV->txn_begin");
		goto out;
	}

	/* look for client record in database, based on eia_clientowner */
	const client_owner4 *owner = &args->eia_clientowner;
	struct nfs_constbuf obuf = { owner->co_ownerid.co_ownerid_len,
				     owner->co_ownerid.co_ownerid_val };
	rc = fsdb_cli_get_byowner(&srv.fsdb, txn, &obuf, 0, &cli);
	if (rc && rc != DB_NOTFOUND) {
		status = NFS4ERR_IO;
		goto out_txn;
	}

	bool have_owner = (rc == 0);

	/* client present; trash-locks and metadata-update modes unsupported */
	if (have_owner) {
		status = NFS4ERR_NOTSUPP;
		goto out_txn;
	}

	/*
	 * create new client record
	 */
	
	cli.flags = args->eia_flags;
	memcpy(cli.verifier, owner->co_verifier, sizeof(cli.verifier));
	cli.owner.owner_len = owner->co_ownerid.co_ownerid_len;
	cli.owner.owner_val = memdup(owner->co_ownerid.co_ownerid_val,
				     owner->co_ownerid.co_ownerid_len);
	if (!cli.owner.owner_val) {
		status = NFS4ERR_SERVERFAULT;
		goto out_txn;
	}

	/*
	 * Attempt to store in database, with random client id.
	 * Continue trying with random client ids until a unique
	 * one is found.
	 */
	unsigned int store_tries = 50000;
	while (store_tries-- > 0) {
		nrand32(&cli.id, 2);

		rc = fsdb_cli_put(&srv.fsdb, txn, DB_NOOVERWRITE, &cli);
		if (rc == 0)
			break;
		if (rc != DB_KEYEXIST) {
			status = NFS4ERR_IO;
			goto out_txn;
		}
	}
	if (rc) {	/* highly unlikely! */
		status = NFS4ERR_SERVERFAULT;
		goto out_txn;
	}

	struct nfs_clientid *clid = clientid_new();
	if (!clid) {
		status = NFS4ERR_NOSPC;
		goto out_txn;
	}
	clid->id_short = cli.id;

	g_hash_table_insert(srv.clid_idx, &clid->id_short, clid);

	const char *my_server_owner = "127.0.0.1";
	const char *my_server_scope = "n/a";

	if (debugging)
		applog(LOG_INFO, "   clientid %016llx, seq %x, flg %x",
			(unsigned long long) cli.id,
			cli.sequence_id,
			cli.flags);

	/* write successful result response */
	WR64(cli.id);
	WR32(cli.sequence_id);
	WR32(cli.flags);
	WR32(SP4_NONE);			/* eir_state_protect */
	WR64(0);			/* eir_server_owner.so_minor_id */
	WRSTR(my_server_owner);		/* eir_server_owner.so_major_id */
	WRSTR(my_server_scope);		/* eir_server_scope */
	WR32(0);			/* eir_server_impl_id size */

	ok_commit = true;

out_txn:
	if (ok_commit) {
		rc = txn->commit(txn, 0);
		if (rc) {
			dbenv->err(dbenv, rc, "DB_ENV->txn_commit");
			status = NFS4ERR_IO;
		}
	} else {
		if (txn->abort(txn))
			dbenv->err(dbenv, rc, "DB_ENV->txn_abort");
	}

out:
	fsdb_cli_free(&cli, false);

	*status_p = htonl(status);
	return status;
}

nfsstat4 nfs_op_create_session(struct nfs_cxn *cxn,
			       const CREATE_SESSION4args *args,
			       struct list_head *writes, struct rpc_write **wr)
{
	uint32_t *status_p;
	nfsstat4 status = NFS4_OK;
	bool ok_commit = false;
	DB_TXN *txn = NULL;
	DB_ENV *dbenv = srv.fsdb.env;
	fsdb_client cli = {};
	fsdb_session sess = {};

	if (debugging)
		applog(LOG_INFO, "op CREATE_SESSION (clid %016llx, seq %x, flg %x)",
			args->csa_clientid,
			args->csa_sequence,
			args->csa_flags);

	status_p = WRSKIP(4);			/* ending status */

	int rc = dbenv->txn_begin(dbenv, NULL, &txn, 0);
	if (rc) {
		status = NFS4ERR_IO;
		dbenv->err(dbenv, rc, "DB_ENV->txn_begin");
		goto out;
	}

	/* lookup the given clientid in db */
	rc = fsdb_cli_get(&srv.fsdb, txn, args->csa_clientid, 0, &cli);
	if (rc) {
		if (rc == DB_NOTFOUND)
			status = NFS4ERR_STALE_CLIENTID;
		else
			status = NFS4ERR_IO;
		goto out_txn;
	}

	/* validate sequenceid matches expectations */
	if (args->csa_sequence != cli.sequence_id) {
		status = NFS4ERR_SEQ_MISORDERED;
		goto out_txn;
	}

	/* confirm client record, if necessary */
	if (!(cli.flags & EXCHGID4_FLAG_CONFIRMED_R)) {
		cli.flags |= EXCHGID4_FLAG_CONFIRMED_R;
		rc = fsdb_cli_put(&srv.fsdb, txn, 0, &cli);
		if (rc) {
			status = NFS4ERR_IO;
			goto out_txn;
		}
	}

	/*
	 * create new session record
	 */
	sess.client = cli.id;
	sess.flags = args->csa_flags;

	/*
	 * Attempt to store in database, with random session id.
	 * Continue trying with random session ids until a unique
	 * one is found.
	 */
	unsigned int store_tries = 50000;
	while (store_tries-- > 0) {
		nrand32(&sess.id, 2);

		rc = fsdb_sess_put(&srv.fsdb, txn, DB_NOOVERWRITE, &sess);
		if (rc == 0)
			break;
		if (rc != DB_KEYEXIST) {
			status = NFS4ERR_IO;
			goto out_txn;
		}
	}
	if (rc) {	/* highly unlikely! */
		status = NFS4ERR_SERVERFAULT;
		goto out_txn;
	}

	if (debugging) {
		char hexbuf[32 + 1];
		applog(LOG_INFO, "   sess id %s, seq %x, flg %x",
			hexstr(hexbuf, &sess.id[0], sizeof(sess.id)),
			args->csa_sequence,
			sess.flags);
	}

	/* write successful result response */
	WRMEM(&sess.id, sizeof(sess.id));	/* csr_sessionid */
	WR32(args->csa_sequence);		/* csr_sequence */
	WR32(sess.flags);			/* csr_flags */

	unsigned int i;			/* csr_{fore,back}_chan_attrs */
	for (i = 0; i < 2; i++) {
		WR32(0);			/* ca_headerpadsize */
		WR32(1024 * 1024);		/* ca_maxrequestsize */
		WR32(1024 * 1024);		/* ca_maxresponsesize */
		WR32(1024 * 1024);		/* ca_maxresponsesize_cached */
		WR32(1000);			/* ca_maxoperations */
		WR32(1000);			/* ca_maxrequests */
		WR32(0);			/* ca_rdma_ird */
	}

	ok_commit = true;

out_txn:
	if (ok_commit) {
		rc = txn->commit(txn, 0);
		if (rc) {
			dbenv->err(dbenv, rc, "DB_ENV->txn_commit");
			status = NFS4ERR_IO;
		}
	} else {
		if (txn->abort(txn))
			dbenv->err(dbenv, rc, "DB_ENV->txn_abort");
	}

out:
	fsdb_cli_free(&cli, false);
	fsdb_sess_free(&sess, false);

	*status_p = htonl(status);
	return status;
}

nfsstat4 nfs_op_sequence(struct nfs_cxn *cxn, const SEQUENCE4args *args,
			 struct list_head *writes, struct rpc_write **wr)
{
	uint32_t *status_p;
	nfsstat4 status = NFS4_OK;

	if (debugging) {
		char hexbuf[32 + 1];
		applog(LOG_INFO, "op SEQUENCE (sess %s, seq %x, slo %x, hslo %x, cache %s",
			hexstr(hexbuf, args->sa_sessionid, sizeof(args->sa_sessionid)),
			args->sa_sequenceid,
			args->sa_slotid,
			args->sa_highest_slotid,
			args->sa_cachethis ? "Y" : "N");
	}

	status_p = WRSKIP(4);			/* ending status */

	int rc = fsdb_sess_get(&srv.fsdb, NULL, &args->sa_sessionid,
			       0, &cxn->sess);
	if (rc) {
		if (rc == DB_NOTFOUND)
			status = NFS4ERR_BADSESSION;
		else
			status = NFS4ERR_IO;
		goto out;
	}

	/* write successful result response */
	WRMEM(&cxn->sess.id, sizeof(cxn->sess.id)); /* sr_sessionid */
	WR32(args->sa_sequenceid);		/* sr_sequenceid */
	WR32(0);				/* sr_slotid */
	WR32(0);				/* sr_highest_slotid */
	WR32(0);				/* sr_target_highest_slotid */
	WR32(0);				/* sr_status_flags */

out:
	*status_p = htonl(status);
	return status;
}

