#ifndef __FSDB_H__
#define __FSDB_H__

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


#include <stdbool.h>
#include <db.h>

struct nfs_inode;
struct nfs_buf;

typedef uint64_t nfsino_t;

struct fsdb_de_key {
	nfsino_t		inum;
	char			name[0];
};

struct fsdb_ug_key {
	uint32_t		is_user;
	char			name[0];
};

struct fsdb_ugidx_key {
	uint32_t		is_user;
	uint32_t		id;
};

struct fsdb_inode {
	nfsino_t		inum;
	nfsino_t		parent;		/* only for directories */
	uint64_t		version;
	uint64_t		size;

	uint64_t		ctime;		/* creation time */
	uint64_t		atime;		/* last-accessed time */
	uint64_t		mtime;		/* last-modified time */

	uint32_t		ftype;
	uint32_t		mode;
	uint32_t		n_link;
	uint32_t		devdata[2];

	char			dataname[32];

	verifier4		create_verf;

	uint16_t		user_len;
	uint16_t		group_len;
	uint16_t		type_len;
	uint16_t		link_len;

	/* variable-length portion of record follows */

	/* user name */
	/* group name */
	/* mime type */
	/* symlink text */
};

struct fsdb {
	char		*home;			/* database home dir */
	char		*key;			/* database AES key */

	DB_ENV		*env;			/* db4 env ptr */
	DB		*inodes;		/* inodes */
	DB		*usergroup;		/* users/groups */
	DB		*ug_idx;		/* u/g index */
	DB		*dirent;		/* dir entries */
};


extern int fsdb_open(struct fsdb *fsdb, unsigned int env_flags,
	unsigned int flags, const char *errpfx, bool do_syslog);
extern void fsdb_close(struct fsdb *fsdb);

extern int fsdb_inode_get(struct fsdb *fsdb, DB_TXN *txn, nfsino_t ino,
			  int flags, struct fsdb_inode **dbino_out);
extern int fsdb_inode_copydec(struct nfs_inode **ino_io,
				const struct fsdb_inode *dbino);
extern int fsdb_inode_getdec(struct fsdb *fsdb, DB_TXN *txn, nfsino_t ino,
			int flags, struct nfs_inode **ino_o);
extern int fsdb_inode_putenc(struct fsdb *fsdb, DB_TXN *txn,
		      const struct nfs_inode *ino, int flags);
extern int fsdb_inode_copyenc(struct fsdb_inode **dbino_o, size_t *dbino_len,
		       const struct nfs_inode *ino);
extern int fsdb_inode_put(struct fsdb *fsdb, DB_TXN *txn,
		   struct fsdb_inode *ino, size_t ino_size, int flags);
extern int fsdb_inode_del(struct fsdb *fsdb, DB_TXN *txn, nfsino_t inum,
			int flags);

extern int fsdb_dirent_get(struct fsdb *fsdb, DB_TXN *txn, nfsino_t inum,
		    const struct nfs_buf *str, int flags, nfsino_t *inum_out);
extern int fsdb_dirent_put(struct fsdb *fsdb, DB_TXN *txn, nfsino_t dir_inum,
		    const struct nfs_buf *str, int flags, nfsino_t de_inum);
extern int fsdb_dirent_del(struct fsdb *fsdb, DB_TXN *txn, nfsino_t dir_inum,
		    const struct nfs_buf *str, int flags);

#endif /* __FSDB_H__ */
