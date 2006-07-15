#include <glib.h>
#include "server.h"
#include "nfs4_prot.h"

static GHashTable *inode_table;
static nfsino_t next_ino = INO_RESERVED_LAST + 1;

struct nfs_inode *inode_get(nfsino_t inum)
{
	g_assert(inode_table != NULL);

	return g_hash_table_lookup(inode_table, GUINT_TO_POINTER(inum));
}

void inode_touch(struct nfs_inode *ino)
{
	ino->version++;
	ino->mtime = current_time.tv_sec;
}

static struct nfs_inode *inode_new(void)
{
	struct nfs_inode *ino = g_new0(struct nfs_inode, 1);
	if (!ino)
		goto out;

	ino->parents = g_array_new(FALSE, FALSE, sizeof(nfsino_t));
	if (!ino->parents)
		goto out_ino;

	inode_touch(ino);	/* sets version, mtime */

	ino->ino = next_ino++;

	goto out;

out_ino:
	g_free(ino);
out:
	return ino;
}

static struct nfs_inode *inode_new_dir(void)
{
	struct nfs_inode *ino = inode_new();
	if (!ino)
		return NULL;

	ino->type = IT_DIR;

	ino->u.dir = g_hash_table_new_full(g_str_hash, g_str_equal,
					   g_free, g_free);
	if (!ino->u.dir) {
		g_free(ino);
		return NULL;
	}

	return ino;
}

bool_t inode_table_init(void)
{
	struct nfs_inode *root;

	inode_table = g_hash_table_new(g_int_hash, g_int_equal);

	root = inode_new_dir();
	if (!root)
		return FALSE;
	root->ino = INO_ROOT;

	g_hash_table_insert(inode_table, GUINT_TO_POINTER(INO_ROOT), root);

	return TRUE;
}

static void inode_free(struct nfs_inode *ino)
{
	g_array_free(ino->parents, TRUE);

	switch (ino->type) {
	case IT_DIR:
		g_assert(ino->u.dir != NULL);
		g_hash_table_destroy(ino->u.dir);
		break;
	case IT_SYMLINK:
		g_free(ino->u.linktext);
		break;
	default:
		/* do nothing */
		break;
	}
}

void inode_unlink(struct nfs_inode *ino, nfsino_t dir_ref)
{
	unsigned int i;

	for (i = 0; i < ino->parents->len; i++)
		if (g_array_index(ino->parents, nfsino_t, i) == dir_ref)
			break;

	if (i < ino->parents->len) {
		g_array_remove_index(ino->parents, i);
		inode_touch(ino);
	}

	if (ino->parents->len == 0) {
		g_hash_table_remove(inode_table, GUINT_TO_POINTER(ino->ino));
		inode_free(ino);
	}
}

