#include <glib.h>
#include "server.h"
#include "nfs4_prot.h"

static GHashTable *inode_table;

struct nfs_inode *ino_get(uint32_t inum)
{
	g_assert(inode_table != NULL);

	return g_hash_table_lookup(inode_table, GUINT_TO_POINTER(inum));
}

void inode_table_init(void)
{
	struct nfs_inode *root;

	inode_table = g_hash_table_new(g_int_hash, g_int_equal);

	root = g_new0(struct nfs_inode, 1);
	root->type = IT_DIR;
	root->u.dir.hash = g_hash_table_new(g_str_hash, g_str_equal);

	g_hash_table_insert(inode_table, GUINT_TO_POINTER(INO_ROOT), root);
}

