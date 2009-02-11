
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
#include <syslog.h>
#include <string.h>
#include <errno.h>
#include <glib.h>
#include "nfs4_prot.h"
#include "server.h"

const char *name_nfs_ftype4[] = {
	[NF4REG] = "NF4REG",
	[NF4DIR] = "NF4DIR",
	[NF4BLK] = "NF4BLK",
	[NF4CHR] = "NF4CHR",
	[NF4LNK] = "NF4LNK",
	[NF4SOCK] = "NF4SOCK",
	[NF4FIFO] = "NF4FIFO",
	[NF4ATTRDIR] = "NF4ATTRDIR",
	[NF4NAMEDATTR] = "NF4NAMEDATTR",
};

static const char *name_nfs4status[] = {
	[NFS4_OK] = "NFS4_OK",
	[NFS4ERR_PERM] = "NFS4ERR_PERM",
	[NFS4ERR_NOENT] = "NFS4ERR_NOENT",
	[NFS4ERR_IO] = "NFS4ERR_IO",
	[NFS4ERR_NXIO] = "NFS4ERR_NXIO",
	[NFS4ERR_ACCESS] = "NFS4ERR_ACCESS",
	[NFS4ERR_EXIST] = "NFS4ERR_EXIST",
	[NFS4ERR_XDEV] = "NFS4ERR_XDEV",
	[NFS4ERR_NOTDIR] = "NFS4ERR_NOTDIR",
	[NFS4ERR_ISDIR] = "NFS4ERR_ISDIR",
	[NFS4ERR_INVAL] = "NFS4ERR_INVAL",
	[NFS4ERR_FBIG] = "NFS4ERR_FBIG",
	[NFS4ERR_NOSPC] = "NFS4ERR_NOSPC",
	[NFS4ERR_ROFS] = "NFS4ERR_ROFS",
	[NFS4ERR_MLINK] = "NFS4ERR_MLINK",
	[NFS4ERR_NAMETOOLONG] = "NFS4ERR_NAMETOOLONG",
	[NFS4ERR_NOTEMPTY] = "NFS4ERR_NOTEMPTY",
	[NFS4ERR_DQUOT] = "NFS4ERR_DQUOT",
	[NFS4ERR_STALE] = "NFS4ERR_STALE",
	[NFS4ERR_BADHANDLE] = "NFS4ERR_BADHANDLE",
	[NFS4ERR_BAD_COOKIE] = "NFS4ERR_BAD_COOKIE",
	[NFS4ERR_NOTSUPP] = "NFS4ERR_NOTSUPP",
	[NFS4ERR_TOOSMALL] = "NFS4ERR_TOOSMALL",
	[NFS4ERR_SERVERFAULT] = "NFS4ERR_SERVERFAULT",
	[NFS4ERR_BADTYPE] = "NFS4ERR_BADTYPE",
	[NFS4ERR_DELAY] = "NFS4ERR_DELAY",
	[NFS4ERR_SAME] = "NFS4ERR_SAME",
	[NFS4ERR_DENIED] = "NFS4ERR_DENIED",
	[NFS4ERR_EXPIRED] = "NFS4ERR_EXPIRED",
	[NFS4ERR_LOCKED] = "NFS4ERR_LOCKED",
	[NFS4ERR_GRACE] = "NFS4ERR_GRACE",
	[NFS4ERR_FHEXPIRED] = "NFS4ERR_FHEXPIRED",
	[NFS4ERR_SHARE_DENIED] = "NFS4ERR_SHARE_DENIED",
	[NFS4ERR_WRONGSEC] = "NFS4ERR_WRONGSEC",
	[NFS4ERR_CLID_INUSE] = "NFS4ERR_CLID_INUSE",
	[NFS4ERR_RESOURCE] = "NFS4ERR_RESOURCE",
	[NFS4ERR_MOVED] = "NFS4ERR_MOVED",
	[NFS4ERR_NOFILEHANDLE] = "NFS4ERR_NOFILEHANDLE",
	[NFS4ERR_MINOR_VERS_MISMATCH] = "NFS4ERR_MINOR_VERS_MISMATCH",
	[NFS4ERR_STALE_CLIENTID] = "NFS4ERR_STALE_CLIENTID",
	[NFS4ERR_STALE_STATEID] = "NFS4ERR_STALE_STATEID",
	[NFS4ERR_OLD_STATEID] = "NFS4ERR_OLD_STATEID",
	[NFS4ERR_BAD_STATEID] = "NFS4ERR_BAD_STATEID",
	[NFS4ERR_BAD_SEQID] = "NFS4ERR_BAD_SEQID",
	[NFS4ERR_NOT_SAME] = "NFS4ERR_NOT_SAME",
	[NFS4ERR_LOCK_RANGE] = "NFS4ERR_LOCK_RANGE",
	[NFS4ERR_SYMLINK] = "NFS4ERR_SYMLINK",
	[NFS4ERR_RESTOREFH] = "NFS4ERR_RESTOREFH",
	[NFS4ERR_LEASE_MOVED] = "NFS4ERR_LEASE_MOVED",
	[NFS4ERR_ATTRNOTSUPP] = "NFS4ERR_ATTRNOTSUPP",
	[NFS4ERR_NO_GRACE] = "NFS4ERR_NO_GRACE",
	[NFS4ERR_RECLAIM_BAD] = "NFS4ERR_RECLAIM_BAD",
	[NFS4ERR_RECLAIM_CONFLICT] = "NFS4ERR_RECLAIM_CONFLICT",
	[NFS4ERR_BADXDR] = "NFS4ERR_BADXDR",
	[NFS4ERR_LOCKS_HELD] = "NFS4ERR_LOCKS_HELD",
	[NFS4ERR_OPENMODE] = "NFS4ERR_OPENMODE",
	[NFS4ERR_BADOWNER] = "NFS4ERR_BADOWNER",
	[NFS4ERR_BADCHAR] = "NFS4ERR_BADCHAR",
	[NFS4ERR_BADNAME] = "NFS4ERR_BADNAME",
	[NFS4ERR_BAD_RANGE] = "NFS4ERR_BAD_RANGE",
	[NFS4ERR_LOCK_NOTSUPP] = "NFS4ERR_LOCK_NOTSUPP",
	[NFS4ERR_OP_ILLEGAL] = "NFS4ERR_OP_ILLEGAL",
	[NFS4ERR_DEADLOCK] = "NFS4ERR_DEADLOCK",
	[NFS4ERR_FILE_OPEN] = "NFS4ERR_FILE_OPEN",
	[NFS4ERR_ADMIN_REVOKED] = "NFS4ERR_ADMIN_REVOKED",
	[NFS4ERR_CB_PATH_DOWN] = "NFS4ERR_CB_PATH_DOWN",
};

bool valid_utf8string(const struct nfs_buf *str)
{
	if (!str || !str->len || !str->val)
		return false;
	if (!g_utf8_validate(str->val, str->len, NULL))
		return false;
	return true;
}

char *cxn_getuser(const struct nfs_cxn *cxn)
{
	char *s = NULL;

	switch (cxn->auth.type) {
	case auth_none:
		/* do nothing */
		break;
	case auth_unix:
		s = id_lookup(idt_user, cxn->auth.u.up.uid);
		break;
	}

	if (!s)
		s = strdup("nobody@localdomain");

	return s;
}

char *cxn_getgroup(const struct nfs_cxn *cxn)
{
	char *s = NULL;

	switch (cxn->auth.type) {
	case auth_none:
		/* do nothing */
		break;
	case auth_unix:
		s = id_lookup(idt_group, cxn->auth.u.up.gid);
		break;
	}

	if (!s)
		s = strdup("nobody@localdomain");

	return s;
}

static nfsstat4 cli_init(const char *host, struct opaque_auth *cred, struct opaque_auth *verf,
			 struct nfs_cxn **cxn_out)
{
	struct nfs_cxn *cxn = calloc(1, sizeof(struct nfs_cxn));
	nfsstat4 status = NFS4_OK;
	uint32_t *p, v, ql;

	if (!cxn) {
		status = NFS4ERR_RESOURCE;
		goto out;
	}

	strncpy(cxn->auth.host, host, sizeof(cxn->auth.host) - 1);

	switch (cred->oa_flavor) {
	case AUTH_NONE:
		syslog(LOG_INFO, "AUTH_NONE");
		cxn->auth.type = auth_none;

		if (debugging > 1)
			syslog(LOG_INFO, "RPC CRED None (len %d)",
				cred->oa_length);
		break;

	case AUTH_SYS:
		if (!cred->oa_base || (cred->oa_length < 16)) {
			syslog(LOG_INFO, "AUTH_SYS null");
			status = NFS4ERR_DENIED;
			goto err_out;
		}

		p = (uint32_t *) cred->oa_base;

		p++;					/* stamp */
		v = ntohl(*p++);			/* machinename len */

		ql = XDR_QUADLEN(v);
		if (cred->oa_length < ((ql + 4) * 4)) {
			syslog(LOG_INFO, "AUTH_SYS null");
			status = NFS4ERR_DENIED;
			goto err_out;
		}

		p += ql;				/* machinename */
		cxn->auth.u.up.uid = ntohl(*p++);	/* uid */
		cxn->auth.u.up.gid = ntohl(*p++);	/* gid */

		/* we ignore the list of gids that follow */

		cxn->auth.type = auth_unix;

		if (debugging > 1)
			syslog(LOG_INFO, "RPC CRED Unix (uid %d gid %d len %d)",
				cxn->auth.u.up.uid,
				cxn->auth.u.up.gid,
				cred->oa_length);
		break;

	default:
		syslog(LOG_INFO, "AUTH unknown");
		status = NFS4ERR_DENIED;
		goto err_out;
	}

out:
	*cxn_out = cxn;
	return status;

err_out:
	free(cxn);
	goto out;
}

static nfsstat4 nfs_op_readlink(struct nfs_cxn *cxn, struct curbuf *cur,
		       struct list_head *writes, struct rpc_write **wr)
{
	nfsstat4 status = NFS4_OK;
	struct nfs_inode *ino;
	char *linktext;

	if (debugging)
		syslog(LOG_INFO, "op READLINK");

	ino = inode_fhdec(NULL, cxn->current_fh);
	if (!ino) {
		status = NFS4ERR_NOFILEHANDLE;
		goto out;
	}
	if (ino->type != NF4LNK) {
		status = NFS4ERR_INVAL;
		goto out;
	}

	linktext = ino->linktext;

	if (debugging)
		syslog(LOG_INFO, "   READLINK -> '%s'", linktext);

out:
	WR32(status);
	if (status == NFS4_OK)
		WRSTR(linktext);
	return status;
}

static nfsstat4 nfs_op_secinfo(struct nfs_cxn *cxn, struct curbuf *cur,
		       struct list_head *writes, struct rpc_write **wr)
{
	nfsstat4 status;
	struct nfs_buf name;
	struct nfs_inode *ino = NULL;

	if (debugging)
		syslog(LOG_INFO, "op SECINFO");

	CURBUF(&name);				/* component name */

	if (!name.len || !g_utf8_validate(name.val, name.len, NULL)) {
		status = NFS4ERR_INVAL;
		goto out;
	}

	status = dir_curfh(NULL, cxn, &ino);
	if (status != NFS4_OK)
		goto out;

out:
	WR32(status);
	if (status == NFS4_OK) {
		WR32(2);		/* secinfo array size */
		WR32(AUTH_SYS);
		WR32(AUTH_NONE);
	}
	return status;
}

static const char *arg_str[] = {
	"<n/a>",
	"<n/a>",
	"<n/a>",
	"ACCESS",
	"CLOSE",
	"COMMIT",
	"CREATE",
	"DELEGPURGE",
	"DELEGRETURN",
	"GETATTR",
	"GETFH",
	"LINK",
	"LOCK",
	"LOCKT",
	"LOCKU",
	"LOOKUP",
	"LOOKUPP",
	"NVERIFY",
	"OPEN",
	"OPENATTR",
	"OPEN_CONFIRM",
	"OPEN_DOWNGRADE",
	"PUTFH",
	"PUTPUBFH",
	"PUTROOTFH",
	"READ",
	"READDIR",
	"READLINK",
	"REMOVE",
	"RENAME",
	"RENEW",
	"RESTOREFH",
	"SAVEFH",
	"SECINFO",
	"SETATTR",
	"SETCLIENTID",
	"SETCLIENTID_CONFIRM",
	"VERIFY",
	"WRITE",
	"RELEASE_LOCKOWNER",
};

static nfsstat4 nfs_op(struct nfs_cxn *cxn, struct curbuf *cur,
		       struct list_head *writes, struct rpc_write **wr)
{
	uint32_t op;

	if (cur->len < 4)
		return NFS4ERR_BADXDR;

	op = CR32();			/* read argop */

	switch (op) {
	case OP_ACCESS:
	case OP_CLOSE:
	case OP_COMMIT:
	case OP_CREATE:
	case OP_GETATTR:
	case OP_GETFH:
	case OP_LINK:
	case OP_LOCK:
	case OP_LOCKT:
	case OP_LOCKU:
	case OP_LOOKUP:
	case OP_LOOKUPP:
	case OP_NVERIFY:
	case OP_OPEN:
	case OP_OPEN_CONFIRM:
	case OP_OPEN_DOWNGRADE:
	case OP_PUTFH:
	case OP_PUTPUBFH:
	case OP_PUTROOTFH:
	case OP_READ:
	case OP_READDIR:
	case OP_READLINK:
	case OP_REMOVE:
	case OP_RENAME:
	case OP_RESTOREFH:
	case OP_SAVEFH:
	case OP_SECINFO:
	case OP_SETATTR:
	case OP_SETCLIENTID:
	case OP_SETCLIENTID_CONFIRM:
	case OP_VERIFY:
	case OP_WRITE:
	case OP_DELEGPURGE:
	case OP_DELEGRETURN:
	case OP_RENEW:
	case OP_RELEASE_LOCKOWNER:
	case OP_OPENATTR:
		WR32(op);			/* write resop */
		break;

	default:
		WR32(NFS4ERR_OP_ILLEGAL);	/* write resop */
		break;
	}

	switch (op) {
	/* db4 conversion complete */
	case OP_ACCESS:
		srv.stats.op_access++;
		return nfs_op_access(cxn, cur, writes, wr);
	case OP_GETFH:
		srv.stats.op_getfh++;
		return nfs_op_getfh(cxn, cur, writes, wr);
	case OP_PUTFH:
		srv.stats.op_putfh++;
		return nfs_op_putfh(cxn, cur, writes, wr);
	case OP_PUTPUBFH:
		srv.stats.op_putpubfh++;
		return nfs_op_putpubfh(cxn, cur, writes, wr);
	case OP_PUTROOTFH:
		srv.stats.op_putrootfh++;
		return nfs_op_putrootfh(cxn, cur, writes, wr);
	case OP_RESTOREFH:
		srv.stats.op_restorefh++;
		return nfs_op_restorefh(cxn, cur, writes, wr);
	case OP_SAVEFH:
		srv.stats.op_savefh++;
		return nfs_op_savefh(cxn, cur, writes, wr);
	case OP_SECINFO:
		srv.stats.op_secinfo++;
		return nfs_op_secinfo(cxn, cur, writes, wr);

	/* needs work for db4 */
	case OP_CLOSE:
		srv.stats.op_close++;
		return nfs_op_close(cxn, cur, writes, wr);
	case OP_COMMIT:
		srv.stats.op_commit++;
		return nfs_op_commit(cxn, cur, writes, wr);
	case OP_CREATE:
		srv.stats.op_create++;
		return nfs_op_create(cxn, cur, writes, wr);
	case OP_GETATTR:
		srv.stats.op_getattr++;
		return nfs_op_getattr(cxn, cur, writes, wr);
	case OP_LINK:
		srv.stats.op_link++;
		return nfs_op_link(cxn, cur, writes, wr);
	case OP_LOCK:
		srv.stats.op_lock++;
		return nfs_op_lock(cxn, cur, writes, wr);
	case OP_LOCKT:
		srv.stats.op_testlock++;
		return nfs_op_testlock(cxn, cur, writes, wr);
	case OP_LOCKU:
		srv.stats.op_unlock++;
		return nfs_op_unlock(cxn, cur, writes, wr);
	case OP_LOOKUP:
		srv.stats.op_lookup++;
		return nfs_op_lookup(cxn, cur, writes, wr);
	case OP_LOOKUPP:
		srv.stats.op_lookupp++;
		return nfs_op_lookupp(cxn, cur, writes, wr);
	case OP_NVERIFY:
		srv.stats.op_nverify++;
		return nfs_op_verify(cxn, cur, writes, wr, true);
	case OP_OPEN:
		srv.stats.op_open++;
		return nfs_op_open(cxn, cur, writes, wr);
	case OP_OPEN_CONFIRM:
		srv.stats.op_open_confirm++;
		return nfs_op_open_confirm(cxn, cur, writes, wr);
	case OP_OPEN_DOWNGRADE:
		srv.stats.op_open_downgrade++;
		return nfs_op_open_downgrade(cxn, cur, writes, wr);
	case OP_READ:
		srv.stats.op_read++;
		return nfs_op_read(cxn, cur, writes, wr);
	case OP_READDIR:
		srv.stats.op_readdir++;
		return nfs_op_readdir(cxn, cur, writes, wr);
	case OP_READLINK:
		srv.stats.op_readlink++;
		return nfs_op_readlink(cxn, cur, writes, wr);
	case OP_RELEASE_LOCKOWNER:
		srv.stats.op_release_lockowner++;
		return nfs_op_release_lockowner(cxn, cur, writes, wr);
	case OP_REMOVE:
		srv.stats.op_remove++;
		return nfs_op_remove(cxn, cur, writes, wr);
	case OP_RENAME:
		srv.stats.op_rename++;
		return nfs_op_rename(cxn, cur, writes, wr);
	case OP_RENEW:
		srv.stats.op_renew++;
		return nfs_op_renew(cxn, cur, writes, wr);
	case OP_SETATTR:
		srv.stats.op_setattr++;
		return nfs_op_setattr(cxn, cur, writes, wr);
	case OP_SETCLIENTID:
		srv.stats.op_setclientid++;
		return nfs_op_setclientid(cxn, cur, writes, wr);
	case OP_SETCLIENTID_CONFIRM:
		srv.stats.op_setclientid_confirm++;
		return nfs_op_setclientid_confirm(cxn, cur, writes, wr);
	case OP_VERIFY:
		srv.stats.op_verify++;
		return nfs_op_verify(cxn, cur, writes, wr, false);
	case OP_WRITE:
		srv.stats.op_write++;
		return nfs_op_write(cxn, cur, writes, wr);

	case OP_DELEGPURGE:
	case OP_DELEGRETURN:
	case OP_OPENATTR:
		if (debugging)
			syslog(LOG_INFO, "compound op %s",
			       (op > 39) ?  "<n/a>" : arg_str[op]);

		srv.stats.op_notsupp++;
		WR32(NFS4ERR_NOTSUPP);		/* op status */
		return NFS4ERR_NOTSUPP;		/* compound status */

	default:
		srv.stats.op_illegal++;
		WR32(NFS4ERR_OP_ILLEGAL);	/* op status */
		return NFS4ERR_OP_ILLEGAL;	/* compound status */
	}

	return NFS4ERR_INVAL;	/* never reached */
}

int nfsproc_null(const char *host, struct opaque_auth *cred, struct opaque_auth *verf,
		  struct curbuf *cur, struct list_head *writes,
		  struct rpc_write **wr)
{
	if (debugging)
		syslog(LOG_ERR, "NULL proc invoked");

	return 0;
}

int nfsproc_compound(const char *host, struct opaque_auth *cred, struct opaque_auth *verf,
		      struct curbuf *cur, struct list_head *writes,
		      struct rpc_write **wr)
{
	struct nfs_buf tag;
	uint32_t *stat_p, *result_p, n_args, minor;
	nfsstat4 status = NFS4_OK;
	unsigned int i = 0, results = 0;
	struct nfs_cxn *cxn = NULL;
	int drc_mask = 0;

	CURBUF(&tag);			/* COMPOUND tag */
	minor = CR32();			/* minor version */
	n_args = CR32();		/* arg array size */

	stat_p = WRSKIP(4);		/* COMPOUND result status */
	WRBUF(&tag);			/* tag */
	result_p = WRSKIP(4);		/* result array size */

	if (!g_utf8_validate(tag.val, tag.len, NULL)) {
		status = NFS4ERR_INVAL;
		goto out;
	}
	if (minor != 0) {
		status = NFS4ERR_MINOR_VERS_MISMATCH;
		goto out;
	}

	status = cli_init(host, cred, verf, &cxn);
	if (status != NFS4_OK)
		goto out;

	/* honestly, this was put here more to shortcut a
	 * pathological case in pynfs.  we don't really have
	 * any inherent limits here.
	 */
	if (n_args > SRV_MAX_COMPOUND_OPS) {
		status = NFS4ERR_RESOURCE;
		goto out;
	}

	for (i = 0; i < n_args; i++) {
		results++;	/* even failed operations have results */

		status = nfs_op(cxn, cur, writes, wr);
		if (status != NFS4_OK)
			break;
	}

out:
	if (debugging || (i > 500))
		syslog(LOG_INFO, "compound end (%u args, %u results, status %s)",
		       n_args, results,
		       name_nfs4status[status]);

	if (cxn) {
		drc_mask = cxn->drc_mask;
		free(cxn);
	}

	if (status == NFS4_OK)
		srv.stats.compound_ok++;
	else
		srv.stats.compound_fail++;

	*stat_p = htonl(status);
	*result_p = htonl(results);

	return drc_mask;
}

