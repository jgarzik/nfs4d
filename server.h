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
};

struct nfs_client {
	nfsino_t		current_fh;
	nfsino_t		save_fh;
};

enum inode_type {
	IT_NONE,
	IT_REG,
	IT_DIR,
	IT_SYMLINK,
};

struct nfs_inode {
	nfsino_t		ino;
	enum inode_type		type;		/* inode type: link, dir, ...*/
	GArray			*parents;	/* list of parent dirs */
	uint64_t		version;
	uint64_t		mtime;		/* last-modified time */

	union {
		GHashTable	*dir;		/* state for a directory */
		gchar		*linktext;	/* state for a symlink */
	} u;
};

struct nfs_dirent {
	nfsino_t		ino;
};


/* global variables */
extern struct timeval current_time;


/* inode.c */
struct nfs_inode *inode_get(nfsino_t inum);
void inode_touch(struct nfs_inode *ino);
bool_t inode_table_init(void);
void inode_unlink(struct nfs_inode *ino, nfsino_t dir_ref);

/* dir.c */
bool_t nfs_op_lookup(struct nfs_client *cli, LOOKUP4args *arg, COMPOUND4res *cres);
bool_t nfs_op_lookupp(struct nfs_client *cli, COMPOUND4res *cres);
bool_t nfs_op_link(struct nfs_client *cli, LINK4args *arg, COMPOUND4res *cres);
bool_t nfs_op_remove(struct nfs_client *cli, REMOVE4args *arg, COMPOUND4res *cres);

/* server.c */
bool_t push_resop(COMPOUND4res *res, const nfs_resop4 *resop, nfsstat4 stat);
bool_t valid_utf8string(utf8string *str);
gchar *copy_utf8string(utf8string *str);
bool_t has_dots(utf8string *str);

#endif /* __SERVER_H__ */
