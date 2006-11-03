#ifndef __SERVER_H__
#define __SERVER_H__

#include <stdint.h>
#include <sys/time.h>
#include <glib.h>
#include "nfs4_prot.h"

typedef uint32_t nfsino_t;

enum {
	INO_ROOT		= 10,
	INO_FIRST		= INO_ROOT,
	INO_RESERVED_LAST	= 999,

	NFS_CLI_CONFIRMED	= (1 << 0),
};

enum server_limits {
	SRV_MAX_LINK		= 0xffffffff,	/* max hard links per inode*/
	SRV_MAX_NAME		= 512,		/* max pathname length */
	SRV_MAX_READ		= 1024 * 128,	/* max contig. read */
	SRV_MAX_WRITE		= 1024 * 128,	/* max contig. write */
};

enum fattr_types {
	FATTR_TYPE_OBJ,
	FATTR_TYPE_FS,
	FATTR_TYPE_SRV,
};

struct nfs_client {
	nfsino_t		current_fh;
	nfsino_t		save_fh;
};

struct nfs_cli_state {
	nfs_client_id4		id;
	unsigned long		flags;
};

struct nfs_inode {
	nfsino_t		ino;
	enum nfs_ftype4		type;		/* inode type: link, dir, ...*/
	GArray			*parents;	/* list of parent dirs */
	uint64_t		version;

	uint64_t		size;

	uint64_t		ctime;		/* creation time */
	uint64_t		atime;		/* last-accessed time */
	uint64_t		mtime;		/* last-modified time */
	uint32_t		mode;
	uint32_t		uid;
	uint32_t		gid;

	union {
		GHashTable	*dir;		/* state for a directory */
		gchar		*linktext;	/* state for a symlink */
		specdata4	devdata;	/* block/chrdev info */
	} u;
};

#define FATTR_DEFINE(a,b,c) \
	fattr4_##b b;

struct nfs_fattr_set {
	uint64_t		bitmap;

#include "fattr.h"
};

#undef FATTR_DEFINE

struct nfs_dirent {
	nfsino_t		ino;
};

struct nfs_server {
	GHashTable		*inode_table;
};

/* global variables */
extern struct timeval current_time;
extern GList *client_list;
extern struct nfs_server srv;

/* inode.c */
struct nfs_inode *inode_get(nfsino_t inum);
void inode_touch(struct nfs_inode *ino);
bool_t inode_table_init(void);
void inode_unlink(struct nfs_inode *ino, nfsino_t dir_ref);
bool_t nfs_op_create(struct nfs_client *cli, CREATE4args *arg, COMPOUND4res *cres);

/* dir.c */
bool_t nfs_op_lookup(struct nfs_client *cli, LOOKUP4args *arg, COMPOUND4res *cres);
bool_t nfs_op_lookupp(struct nfs_client *cli, COMPOUND4res *cres);
bool_t nfs_op_link(struct nfs_client *cli, LINK4args *arg, COMPOUND4res *cres);
bool_t nfs_op_remove(struct nfs_client *cli, REMOVE4args *arg, COMPOUND4res *cres);
bool_t nfs_op_rename(struct nfs_client *cli, RENAME4args *arg, COMPOUND4res *cres);
enum nfsstat4 dir_add(struct nfs_inode *dir_ino, utf8string *name_in,
		      nfsino_t inum);
void dirent_free(gpointer p);

/* fattr.c */
bool_t fattr_encode(fattr4 *raw, struct nfs_fattr_set *attr);
bool_t fattr_decode(fattr4 *raw, struct nfs_fattr_set *attr);
void fattr_free(struct nfs_fattr_set *attr);
void fattr_fill_server(struct nfs_fattr_set *attr);
void fattr_fill_fs(struct nfs_fattr_set *attr);
void fattr_fill_obj(struct nfs_inode *ino, struct nfs_fattr_set *attr);

/* server.c */
bool_t push_resop(COMPOUND4res *res, const nfs_resop4 *resop, nfsstat4 stat);
bool_t valid_utf8string(utf8string *str);
gchar *copy_utf8string(utf8string *str);
bool_t has_dots(utf8string *str);
void nfs_fh_set(nfs_fh4 *fh, nfsino_t fh_int);

#endif /* __SERVER_H__ */
