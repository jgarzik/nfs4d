#ifndef __SERVER_H__
#define __SERVER_H__

#include <stdint.h>
#include <glib.h>
#include "nfs4_prot.h"

enum {
	INO_ROOT		= 10,
	INO_FIRST		= INO_ROOT,
	INO_RESERVED_LAST	= 999,
};

struct nfs_client {
	uint32_t		current_fh;
	uint32_t		save_fh;
};

enum inode_type {
	IT_NONE,
	IT_REG,
	IT_DIR,
	IT_SYMLINK,
};

struct nfs_inode {
	enum inode_type		type;

	union {
		struct {
			GHashTable	*hash;
			uint32_t	parent;
		} dir;

		gchar		*linktext;
	} u;
};

struct nfs_dirent {
	uint32_t		ino;
};

/* inode.c */
struct nfs_inode *ino_get(uint32_t inum);
void inode_table_init(void);

/* dir.c */
bool_t nfs_op_lookup(struct nfs_client *cli, LOOKUP4args *arg, COMPOUND4res *cres);
bool_t nfs_op_lookupp(struct nfs_client *cli, COMPOUND4res *cres);

/* server.c */
bool_t push_resop(COMPOUND4res *res, const nfs_resop4 *resop, nfsstat4 stat);
bool_t valid_utf8string(utf8string *str);

#endif /* __SERVER_H__ */
