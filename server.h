#ifndef __SERVER_H__
#define __SERVER_H__

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

#include <stdint.h>
#include <stdbool.h>
#include <sys/time.h>
#include <glib.h>
#include <rpc/types.h>
#include <rpc/auth.h>
#include <rpc/rpc_msg.h>
#include <rpc/xdr.h>
#include <event.h>
#include "nfs4_prot.h"
#include "elist.h"
#include "nfscommon.h"
#include "fsdb.h"

struct nfs_owner;
struct nfs_openfile;
struct server_socket;

#define SRV_MAGIC		"J721"

/* portability */
#ifndef HOST_NAME_MAX
#define HOST_NAME_MAX	64
#endif

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#define XDR_QUADLEN(l)		(((l) + 3) >> 2)

#define CUR_SKIP(count)		cur_skip(cur, (count))
#define CR32()			cur_read32(cur)
#define CR64()			cur_read64(cur)
#define CURMEM(count)		cur_readmem(cur, (count))
#define CURBUF(buf_ptr)		cur_readbuf(cur, (buf_ptr))
#define CURMAP()		cur_readmap(cur)

#define WRSKIP(count)		wr_skip(writes, wr, (count))
#define WR32(val)		wr_write32(writes, wr, (val))
#define WR64(val)		wr_write64(writes, wr, (val))
#define WRBUF(buf_ptr)		wr_buf(writes, wr, (buf_ptr))
#define WRSTR(str)		wr_str(writes, wr, (str))
#define WRMEM(buf, len)		wr_mem(writes, wr, (buf), (len))
#define WRSID(sid_ptr)		wr_sid(writes, wr, (sid_ptr))
#define WRMAP(bitmap)		wr_map(writes, wr, (bitmap))

enum {
	NFS_CLI_CONFIRMED	= (1 << 0),

	RPC_WRITE_BUFSZ		= 8192,
};

enum blob_hash_init_info {
	BLOB_HASH_INIT		= 5381UL
};

enum server_limits {
	SRV_MAX_LINK		= 0xffffffff,	/* max hard links per inode*/
	SRV_MAX_NAME		= 255,		/* max pathname length */
	SRV_MAX_READ		= 1024 * 128,	/* max contig. read */
	SRV_MAX_WRITE		= 1024 * 128,	/* max contig. write */

	SRV_LEASE_TIME		= 3 * 60,
	SRV_DRC_TIME		= 4 * 60,
	SRV_STATE_DEATH		= 5 * 60,
	SRV_CLID_DEATH		= SRV_LEASE_TIME * 2,
	SRV_SPACE_USED_TTL	= 10,
	SRV_GARBAGE_TIME	= 45,

	SRV_CHKPT_SEC		= 60 * 5,	/* secs between db4 chkpt */

	SRV_MAX_COMPOUND_OPS	= 3000,		/* arbitrary */

	SRV_STATE_HIGH_WAT	= 100000,	/* start gc at this size */
	SRV_STATE_LOW_WAT	= 33000,	/* stop gc at this limit */

	MODE4_ALL		= MODE4_SUID |
				  MODE4_SGID |
				  MODE4_SVTX |
				  MODE4_RUSR |
				  MODE4_WUSR |
				  MODE4_XUSR |
				  MODE4_RGRP |
				  MODE4_WGRP |
				  MODE4_XGRP |
				  MODE4_ROTH |
				  MODE4_WOTH |
				  MODE4_XOTH,
};

enum server_fs_settings {
	SRV_FH_EXP_TYPE		= FH4_PERSISTENT,
};

enum big_server_fs_settings {
	SRV_MAX_FILESIZE	= 0xffffffffULL,
};

enum other_blob_info {
	BLOB_MAGIC		= 0xdeadbeef
};

enum fattr_types {
	FATTR_TYPE_OBJ,
	FATTR_TYPE_FS,
	FATTR_TYPE_SRV,
};

enum {
	fattr_mandatory_ro_mask =
		1ULL << FATTR4_SUPPORTED_ATTRS |
		1ULL << FATTR4_TYPE |
		1ULL << FATTR4_FH_EXPIRE_TYPE |
		1ULL << FATTR4_CHANGE |
		1ULL << FATTR4_LINK_SUPPORT |
		1ULL << FATTR4_SYMLINK_SUPPORT |
		1ULL << FATTR4_NAMED_ATTR |
		1ULL << FATTR4_FSID |
		1ULL << FATTR4_UNIQUE_HANDLES |
		1ULL << FATTR4_LEASE_TIME |
		1ULL << FATTR4_RDATTR_ERROR |
		1ULL << FATTR4_FILEHANDLE,

	fattr_mandatory_rw_mask =
		1ULL << FATTR4_SIZE,

	fattr_write_only_mask =
		1ULL << FATTR4_TIME_ACCESS_SET |
		1ULL << FATTR4_TIME_MODIFY_SET,

	fattr_read_write_mask = fattr_mandatory_rw_mask |
#if 0
		1ULL << FATTR4_ACL |
#endif
		1ULL << FATTR4_MIMETYPE |
		1ULL << FATTR4_MODE |
		1ULL << FATTR4_OWNER |
		1ULL << FATTR4_OWNER_GROUP |
		1ULL << FATTR4_TIME_CREATE,

	fattr_read_only_mask = fattr_mandatory_ro_mask |
		1ULL << FATTR4_ACLSUPPORT |
		1ULL << FATTR4_CANSETTIME |
		1ULL << FATTR4_CASE_INSENSITIVE |
		1ULL << FATTR4_CASE_PRESERVING |
		1ULL << FATTR4_CHOWN_RESTRICTED |
		1ULL << FATTR4_FILEID |
		1ULL << FATTR4_FILES_AVAIL |
		1ULL << FATTR4_FILES_FREE |
		1ULL << FATTR4_FILES_TOTAL |
		1ULL << FATTR4_FS_LOCATIONS |
		1ULL << FATTR4_HOMOGENEOUS |
		1ULL << FATTR4_MAXFILESIZE |
		1ULL << FATTR4_MAXLINK |
		1ULL << FATTR4_MAXNAME |
		1ULL << FATTR4_MAXREAD |
		1ULL << FATTR4_MAXWRITE |
		1ULL << FATTR4_NO_TRUNC |
		1ULL << FATTR4_NUMLINKS |
#if 0
		1ULL << FATTR4_QUOTA_AVAIL_HARD |
		1ULL << FATTR4_QUOTA_AVAIL_SOFT |
		1ULL << FATTR4_QUOTA_USED |
#endif
		1ULL << FATTR4_RAWDEV |
		1ULL << FATTR4_SPACE_AVAIL |
		1ULL << FATTR4_SPACE_FREE |
		1ULL << FATTR4_SPACE_TOTAL |
		1ULL << FATTR4_SPACE_USED |
		1ULL << FATTR4_TIME_ACCESS |
		1ULL << FATTR4_TIME_DELTA |
		1ULL << FATTR4_TIME_METADATA |
		1ULL << FATTR4_TIME_MODIFY |
		1ULL << FATTR4_MOUNTED_ON_FILEID,

	fattr_supported_mask =
		fattr_read_only_mask |
		fattr_read_write_mask |
		fattr_write_only_mask,
};

enum id_type {
	idt_user,
	idt_group
};

enum drc_bits {
	drc_lock		= (1 << 0),
	drc_unlock		= (1 << 1),
	drc_open		= (1 << 2),
	drc_close		= (1 << 3),
	drc_setcid		= (1 << 4),
	drc_setcidconf		= (1 << 5),
};

struct blob {
	unsigned int		magic;
	unsigned int		len;
	void			*buf;
};

struct curbuf {
	const char	*buf_start;
	const char	*buf;

	unsigned int	len_total;
	unsigned int	len;
};

struct refbuf {
	void			*buf;
	unsigned int		len;
	unsigned int		refcnt;
};

struct rpc_write {
	char			*buf;
	unsigned int		len;		/* data buffer space used */

	struct refbuf		*rbuf;

	struct list_head	node;
};

struct nfs_buf {
	unsigned int		len;
	char			*val;
};

struct nfs_constbuf {
	unsigned int		len;
	const char		*val;
};

struct nfs_stateid {
	uint32_t		seqid;
	uint32_t		id;
	char			server_verf[4];
	char			server_magic[4];
};

struct nfs_fattr_set {
	uint64_t			bitmap;

	uint64_t			supported_attrs;

	fattr4_type			type;
	fattr4_fh_expire_type		fh_expire_type;
	fattr4_change			change;
	fattr4_size			size;
	fattr4_link_support		link_support;
	fattr4_symlink_support		symlink_support;
	fattr4_named_attr		named_attr;
	fattr4_fsid			fsid;
	fattr4_unique_handles		unique_handles;
	fattr4_lease_time		lease_time;
	fattr4_rdattr_error		rdattr_error;
	fattr4_acl			acl;
	fattr4_aclsupport		aclsupport;
	fattr4_archive			archive;
	fattr4_cansettime		cansettime;
	fattr4_case_insensitive		case_insensitive;
	fattr4_case_preserving		case_preserving;
	fattr4_chown_restricted		chown_restricted;

	nfsino_t			filehandle;

	fattr4_fileid			fileid;
	fattr4_files_avail		files_avail;
	fattr4_files_free		files_free;
	fattr4_files_total		files_total;
	fattr4_fs_locations		fs_locations;
	fattr4_hidden			hidden;
	fattr4_homogeneous		homogeneous;
	fattr4_maxfilesize		maxfilesize;
	fattr4_maxlink			maxlink;
	fattr4_maxname			maxname;
	fattr4_maxread			maxread;
	fattr4_maxwrite			maxwrite;

	struct nfs_buf			mimetype;

	fattr4_mode			mode;
	fattr4_no_trunc			no_trunc;
	fattr4_numlinks			numlinks;

	struct nfs_buf			owner;
	struct nfs_buf			owner_group;

	fattr4_quota_avail_hard		quota_avail_hard;
	fattr4_quota_avail_soft		quota_avail_soft;
	fattr4_quota_used		quota_used;
	fattr4_rawdev			rawdev;
	fattr4_space_avail		space_avail;
	fattr4_space_free		space_free;
	fattr4_space_total		space_total;
	fattr4_space_used		space_used;
	fattr4_system			system;
	fattr4_time_access		time_access;

	nfstime4			time_access_set;

	fattr4_time_backup		time_backup;
	fattr4_time_create		time_create;
	fattr4_time_delta		time_delta;
	fattr4_time_metadata		time_metadata;
	fattr4_time_modify		time_modify;

	nfstime4			time_modify_set;

	fattr4_mounted_on_fileid	mounted_on_fileid;
};

enum cxn_auth_type {
	auth_none,
	auth_unix
};

struct cxn_auth {
	char				host[64];
	enum cxn_auth_type		type;

	union {
		struct {
			unsigned int	stamp;
			char		machine[256];
			unsigned int	uid;
			unsigned int	gid;
		} up;
	} u;
};

struct nfs_fh {
#ifdef NFSD_INO64
	nfsino_t		inum;
#else
	nfsino_t		inum;
	uint32_t		reserved1;
#endif
};

struct nfs_cxn {
	struct nfs_fh		current_fh;
	struct nfs_fh		save_fh;

	struct cxn_auth		auth;		/* RPC creds */

	fsdb_session		sess;

	int			drc_mask;
};

struct nfs_lock {
	uint64_t		ofs;
	uint64_t		len;

	struct list_head	node;

	nfs_lock_type4		type;
};

enum nfs_state_type {
	nst_any,				/* an invalid type */
	nst_dead,
	nst_open,
	nst_lock
};

enum nfs_state_flags {
	nsf_expired		= (1 << 0),
	nsf_confirmed		= (1 << 1),
	nsf_north_carolina,
	nsf_rhode_island,
	nsf_georgia,
	nsf_maine,
};

struct nfs_owner {
	clientid4		cli;		/* short clientid */

	char			*owner;		/* lock/open owner */

	enum nfs_state_type	type;		/* nst_xxx */

	uint32_t		cli_next_seq;

	struct nfs_owner	*open_owner;

	struct list_head	openfiles;
	struct list_head	cli_node;
};

struct nfs_openfile {
	struct nfs_owner	*owner;

	nfsino_t		inum;

	enum nfs_state_type	type;		/* nst_xxx */

	unsigned long		flags;		/* nsf_xxx */

	uint32_t		id;		/* our short id */

	uint32_t		my_seq;

	uint32_t		share_access;
	uint32_t		share_deny;

	struct list_head	lock_list;
	struct nfs_openfile	*lock_open;

	struct list_head	inode_node;
	struct list_head	owner_node;

	struct list_head	death_node;
	uint64_t		death_time;
};

struct nfs_inode {
	nfsino_t		inum;
	nfsino_t		parent;		/* only for directories */

	enum nfs_ftype4		type;		/* inode type: link, dir, ...*/
	uint64_t		version;

	verifier4		create_verf;

	uint64_t		size;

	uint64_t		ctime;		/* creation time */
	uint64_t		atime;		/* last-accessed time */
	uint64_t		mtime;		/* last-modified time */
	uint32_t		mode;
	uint32_t		n_link;

	char			*user;
	char			*group;
	char			*mimetype;

	char			*linktext;	/* state for a symlink */
	uint32_t		devdata[2];	/* "" blk/chrdev */
};

struct nfs_server_stats {
	unsigned long long	sock_rx_bytes;
	unsigned long long	sock_tx_bytes;
	unsigned long long	read_bytes;
	unsigned long long	write_bytes;
	unsigned long long	drc_store_bytes;

	unsigned long		rpc_msgs;

	unsigned long		op_access;
	unsigned long		op_close;
	unsigned long		op_commit;
	unsigned long		op_create;
	unsigned long		op_create_session;
	unsigned long		op_exchange_id;
	unsigned long		op_getattr;
	unsigned long		op_getfh;
	unsigned long		op_link;
	unsigned long		op_lock;
	unsigned long		op_testlock;
	unsigned long		op_unlock;
	unsigned long		op_lookup;
	unsigned long		op_lookupp;
	unsigned long		op_nverify;
	unsigned long		op_open;
	unsigned long		op_open_confirm;
	unsigned long		op_open_downgrade;
	unsigned long		op_putfh;
	unsigned long		op_putpubfh;
	unsigned long		op_putrootfh;
	unsigned long		op_read;
	unsigned long		op_readdir;
	unsigned long		op_readlink;
	unsigned long		op_release_lockowner;
	unsigned long		op_remove;
	unsigned long		op_rename;
	unsigned long		op_renew;
	unsigned long		op_restorefh;
	unsigned long		op_savefh;
	unsigned long		op_secinfo;
	unsigned long		op_sequence;
	unsigned long		op_setattr;
	unsigned long		op_setclientid;
	unsigned long		op_setclientid_confirm;
	unsigned long		op_verify;
	unsigned long		op_write;

	unsigned long		op_notsupp;
	unsigned long		op_illegal;

	unsigned long		proc_null;
	unsigned long		proc_compound;

	unsigned long		compound_ok;
	unsigned long		compound_fail;

	unsigned long		openfile_alloc;
	unsigned long		openfile_free;
	unsigned long		clid_alloc;
	unsigned long		clid_free;

	unsigned long		drc_free;
	unsigned long		drc_store;
	unsigned long		drc_hits;
	unsigned long		drc_misses;

	unsigned long		tcp_accept;

	unsigned long		event;
	unsigned long		max_evt;
	unsigned long		poll;
	unsigned long		opt_write;
};

struct nfs_server {
	GHashTable		*clid_idx;

	GHashTable		*openfiles;

	struct list_head	dead;

	unsigned int		lease_time;

	verifier4		instance_verf;

	char			*localdom;

	char			*data_dir;
	char			*metadata_dir;

	GList			*sockets;

	struct event		chkpt_timer;	/* db4 checkpoint timer */

	struct fsdb		fsdb;

	struct nfs_server_stats	stats;
};

struct nfs_access {
	/* input */
	struct nfs_stateid	*sid;
	struct nfs_inode	*ino;
	uint32_t		op;

	uint32_t		locktype;

	uint64_t		clientid;
	struct nfs_buf		*owner;

	uint32_t		share_access;
	uint32_t		share_deny;

	uint64_t		ofs;
	uint64_t		len;

	/* output */
	struct nfs_openfile	*self;

	struct nfs_openfile	*match;
};

/* global variables */
extern struct nfs_server srv;
extern int debugging;

/* data.c */
extern nfsstat4 nfs_op_commit(struct nfs_cxn *cxn, const COMMIT4args *,
		       struct list_head *writes, struct rpc_write **wr);
extern nfsstat4 nfs_op_write(struct nfs_cxn *cxn, const WRITE4args *,
		       struct list_head *writes, struct rpc_write **wr);
extern nfsstat4 nfs_op_read(struct nfs_cxn *cxn, const READ4args *,
		       struct list_head *writes, struct rpc_write **wr);
extern nfsstat4 nfs_op_lock(struct nfs_cxn *cxn, const LOCK4args *,
		       struct list_head *writes, struct rpc_write **wr);
extern nfsstat4 nfs_op_testlock(struct nfs_cxn *cxn, const LOCKT4args *,
		       struct list_head *writes, struct rpc_write **wr);
extern nfsstat4 nfs_op_unlock(struct nfs_cxn *cxn, const LOCKU4args *,
		       struct list_head *writes, struct rpc_write **wr);

/* dir.c */
extern nfsstat4 nfs_op_lookup(struct nfs_cxn *cxn, const LOOKUP4args *,
		       struct list_head *writes, struct rpc_write **wr);
extern nfsstat4 nfs_op_lookupp(struct nfs_cxn *cxn,
		       struct list_head *writes, struct rpc_write **wr);
extern nfsstat4 nfs_op_link(struct nfs_cxn *cxn, const LINK4args *,
		       struct list_head *writes, struct rpc_write **wr);
extern nfsstat4 nfs_op_remove(struct nfs_cxn *cxn, const REMOVE4args *,
		       struct list_head *writes, struct rpc_write **wr);
extern nfsstat4 nfs_op_rename(struct nfs_cxn *cxn, const RENAME4args *,
		       struct list_head *writes, struct rpc_write **wr);
extern nfsstat4 nfs_op_readdir(struct nfs_cxn *cxn, const READDIR4args *,
		       struct list_head *writes, struct rpc_write **wr);
extern enum nfsstat4 dir_add(DB_TXN *txn, struct nfs_inode *dir_ino,
		      const struct nfs_buf *name_in,
		      struct nfs_inode *ent_ino);
nfsstat4 dir_curfh(DB_TXN *txn, const struct nfs_cxn *cxn,
	struct nfs_inode **ino_out, int flags);
extern nfsstat4 dir_lookup(DB_TXN *txn, const struct nfs_inode *dir_ino,
		    const struct nfs_buf *str, int flags,
		    nfsino_t *inum_out);
void nfs_readdir_free(READDIR4res *res);

/* fattr.c */
extern nfsstat4 copy_attr(struct nfs_fattr_set *attr, const fattr4 *attr4);
extern nfsstat4 wr_fattr(const struct nfs_fattr_set *attr, uint64_t *bitmap_out,
		     struct list_head *writes, struct rpc_write **wr);
extern bool fattr_decode(fattr4 *raw, struct nfs_fattr_set *attr);
extern unsigned int fattr_size(const struct nfs_fattr_set *attr);
extern void fattr_free(struct nfs_fattr_set *attr);
extern void fattr_fill(const struct nfs_inode *ino, struct nfs_fattr_set *attr);
extern void print_fattr(const char *pfx, const struct nfs_fattr_set *attr);
extern void print_fattr_bitmap(const char *pfx, uint64_t bitmap);

/* fh.c */
extern nfsstat4 nfs_op_getfh(struct nfs_cxn *cxn,
			     struct list_head *writes, struct rpc_write **wr);
extern nfsstat4 nfs_op_putfh(struct nfs_cxn *cxn, const PUTFH4args *,
			     struct list_head *writes, struct rpc_write **wr);
extern nfsstat4 nfs_op_putrootfh(struct nfs_cxn *cxn,
			     struct list_head *writes, struct rpc_write **wr);
extern nfsstat4 nfs_op_putpubfh(struct nfs_cxn *cxn,
			     struct list_head *writes, struct rpc_write **wr);
extern nfsstat4 nfs_op_restorefh(struct nfs_cxn *cxn,
			     struct list_head *writes, struct rpc_write **wr);
extern nfsstat4 nfs_op_savefh(struct nfs_cxn *cxn,
			     struct list_head *writes, struct rpc_write **wr);

/* id.c */
extern char *id_lookup_name(enum id_type type, const char *name, size_t name_len);
extern char *id_lookup(enum id_type type, unsigned int id);

/* inode.c */
extern nfsstat4 nfs_op_access(struct nfs_cxn *cxn, const ACCESS4args *,
			      struct list_head *writes, struct rpc_write **wr);
extern nfsstat4 nfs_op_getattr(struct nfs_cxn *cxn, const GETATTR4args *,
			       struct list_head *writes, struct rpc_write **wr);
extern nfsstat4 nfs_op_setattr(struct nfs_cxn *cxn, const SETATTR4args *,
			       struct list_head *writes, struct rpc_write **wr);
extern nfsstat4 nfs_op_create(struct nfs_cxn *cxn, const CREATE4args *,
			      struct list_head *writes, struct rpc_write **wr);
extern nfsstat4 nfs_op_verify(struct nfs_cxn *cxn, const VERIFY4args *,
			      struct list_head *writes, struct rpc_write **wr,
			      bool nverify);
extern void inode_openfile_add(struct nfs_inode *ino, struct nfs_openfile *of);
extern void inode_free(struct nfs_inode *ino);
extern struct nfs_inode *inode_getdec(DB_TXN *txn, nfsino_t inum, int flags);
extern bool inode_check(DB_TXN *txn, nfsino_t inum);
extern int inode_touch(DB_TXN *txn, struct nfs_inode *ino);
extern int inode_unlink(DB_TXN *txn, struct nfs_inode *ino);
extern nfsstat4 inode_add(DB_TXN *txn, struct nfs_inode *dir_ino,
		   struct nfs_inode *new_ino, const struct nfs_fattr_set *attr,
		   const struct nfs_buf *name, uint64_t *attrset,
		   change_info4 *cinfo);
extern nfsstat4 inode_new_type(DB_TXN *txn, struct nfs_cxn *cxn, uint32_t objtype,
			const struct nfs_inode *dir_ino,
			const struct nfs_buf *linkdata,
			const uint32_t *specdata,
			struct nfs_inode **ino_out);
extern enum nfsstat4 inode_apply_attrs(DB_TXN *txn, struct nfs_inode *ino,
				const struct nfs_fattr_set *attr,
			        uint64_t *bitmap_set_out,
			        struct nfs_stateid *sid,
			        bool in_setattr);

/* main.c */
extern struct refbuf pad_rb;
extern char my_hostname[];

extern uint64_t srv_space_used(void);
extern uint64_t srv_space_free(void);
extern void syslogerr(const char *prefix);
extern void syslogerr2(const char *pfx1, const char *pfx2);
extern const void *cur_skip(struct curbuf *cur, unsigned int n);
extern uint32_t cur_read32(struct curbuf *cur);
extern uint64_t cur_read64(struct curbuf *cur);
extern uint64_t cur_readmap(struct curbuf *cur);
extern const void *cur_readmem(struct curbuf *cur, unsigned int n);
extern void cur_readbuf(struct curbuf *cur, struct nfs_buf *nb);
extern void wr_free(struct rpc_write *wr);
extern struct rpc_write *wr_alloc(unsigned int n);
extern struct rpc_write *wr_ref(struct refbuf *rb, unsigned int ofs,
			 unsigned int len);
extern uint32_t *wr_write32(struct list_head *writes, struct rpc_write **wr_io,uint32_t val);
extern uint64_t *wr_write64(struct list_head *writes, struct rpc_write **wr_io,uint64_t val);
extern void *wr_skip(struct list_head *writes, struct rpc_write **wr_io,
		     unsigned int n);
extern void *wr_buf(struct list_head *writes, struct rpc_write **wr_io,
		    const struct nfs_buf *nb);
extern void *wr_str(struct list_head *writes, struct rpc_write **wr_io,
			const char *s);
extern void *wr_mem(struct list_head *writes, struct rpc_write **wr_io,
			const void *buf, unsigned int len);
extern void *wr_sid(struct list_head *writes, struct rpc_write **wr_io,
			const struct nfs_stateid *sid);
extern void *wr_map(struct list_head *writes, struct rpc_write **wr_io,
			uint64_t bitmap);

/* open.c */
extern nfsstat4 nfs_op_open(struct nfs_cxn *cxn, const OPEN4args *,
			    struct list_head *writes, struct rpc_write **wr);
extern nfsstat4 nfs_op_open_downgrade(struct nfs_cxn *cxn, const OPEN_DOWNGRADE4args *,
			     struct list_head *writes, struct rpc_write **wr);
extern nfsstat4 nfs_op_close(struct nfs_cxn *cxn, const CLOSE4args *,
			     struct list_head *writes, struct rpc_write **wr);

/* server.c */
extern const char *status2str(nfsstat4 status);
extern char *cxn_getuser(const struct nfs_cxn *cxn);
extern char *cxn_getgroup(const struct nfs_cxn *cxn);

extern void mk_datapfx(char *datapfx, nfsino_t inum);
extern bool valid_utf8string(const struct nfs_buf *str);
extern int nfsproc_null(const char *host, struct opaque_auth *cred, struct opaque_auth *verf,
			 struct curbuf *cur, struct list_head *writes,
			 struct rpc_write **wr);
extern int nfsproc_compound(const char *host, struct opaque_auth *cred, struct opaque_auth *verf,
			     struct curbuf *cur, struct list_head *writes,
			     struct rpc_write **wr);

/* state.c */
extern guint clientid_hash(gconstpointer key_p);
extern gboolean clientid_equal(gconstpointer a_p, gconstpointer b_p);
extern struct list_head ino_openfile_list;
extern bool cli_new_owner(clientid4, char *);
extern void state_gc(void);
extern bool stateid_valid(const struct nfs_stateid *sid);
extern struct nfs_state *state_new(enum nfs_state_type type, struct nfs_buf *owner);
extern nfsstat4 access_ok(struct nfs_access *ac);
extern nfsstat4 clientid_test(clientid4 id);
extern void client_free(gpointer data);
extern void openfile_free(gpointer data);
extern uint32_t gen_stateid(void);
extern nfsstat4 nfs_op_exchange_id(struct nfs_cxn *cxn, const EXCHANGE_ID4args *,
			     struct list_head *writes, struct rpc_write **wr);
extern nfsstat4 nfs_op_create_session(struct nfs_cxn *cxn, const CREATE_SESSION4args *,
			     struct list_head *writes, struct rpc_write **wr);
extern nfsstat4 nfs_op_sequence(struct nfs_cxn *cxn, const SEQUENCE4args *,
			     struct list_head *writes, struct rpc_write **wr);
extern void rand_verifier(verifier4 *verf);

extern void cli_owner_add(struct nfs_owner *owner);
extern void owner_free(struct nfs_owner *owner);
extern struct nfs_owner *owner_new(enum nfs_state_type type, struct nfs_buf *owner);
extern nfsstat4 owner_lookup_name(clientid4 id, struct nfs_buf *owner,
				struct nfs_owner **owner_out);

extern struct nfs_openfile *openfile_new(enum nfs_state_type type, struct nfs_owner *o);
extern nfsstat4 openfile_lookup_owner(struct nfs_owner *,
					struct nfs_inode *,
					struct nfs_openfile **);
extern nfsstat4 openfile_lookup(struct nfs_stateid *,
				struct nfs_inode *,
				enum nfs_state_type type,
				struct nfs_openfile **);
extern void openfile_trash(struct nfs_openfile *, bool);


static inline struct refbuf *refbuf_ref(struct refbuf *rb)
{
	rb->refcnt++;
	return rb;
}

static inline bool nfs_seqid_inc_ok(nfsstat4 status)
{
	switch (status) {
	case NFS4ERR_BAD_SEQID:
	case NFS4ERR_STALE_CLIENTID:
	case NFS4ERR_STALE_STATEID:
	case NFS4ERR_BAD_STATEID:
	case NFS4ERR_BADXDR:
	case NFS4ERR_RESOURCE:
	case NFS4ERR_NOFILEHANDLE:
		return false;

	default:
		return true;
	}

	/* not reached */
}

static inline struct nfs_inode *inode_fhdec(DB_TXN *txn, struct nfs_fh fh,
					    int flags)
{
	return inode_getdec(txn, fh.inum, flags);
}

static inline bool inode_fhcheck(DB_TXN *txn, struct nfs_fh fh)
{
	return inode_check(txn, fh.inum);
}

static inline bool valid_fh(struct nfs_fh fh)
{
	if (!fh.inum)
		return false;

	return true;
}

static inline bool fh_equal(struct nfs_fh a, struct nfs_fh b)
{
	return (a.inum == b.inum);
}

static inline void fh_set(struct nfs_fh *fh, nfsino_t inum)
{
	fh->inum = inum;
}

static inline uint64_t bitmap4_decode(const bitmap4 *map)
{
	uint64_t v = 0;

	if (map->bitmap4_len > 0)
		v |= map->bitmap4_val[0];
	if (map->bitmap4_len > 1)
		v |= (((uint64_t)map->bitmap4_val[1]) << 32ULL);

	return v;
}

static inline void copy_sid(struct nfs_stateid *sid, const stateid4 *sid4)
{
	sid->seqid = sid4->seqid;

	/* FIXME: endian */
	memcpy(&sid->id, &sid4->other[0], sizeof(sid->id));
	memcpy(&sid->server_verf, &sid4->other[4], sizeof(sid->server_verf));
	memcpy(&sid->server_magic, &sid4->other[8], sizeof(sid->server_magic));
}

#endif /* __SERVER_H__ */
