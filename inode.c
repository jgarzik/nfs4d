#include <string.h>
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

	ino->type = NF4DIR;

	ino->u.dir = g_hash_table_new_full(g_str_hash, g_str_equal,
					   g_free, g_free);
	if (!ino->u.dir) {
		g_free(ino);
		return NULL;
	}

	return ino;
}

static struct nfs_inode *inode_new_dev(enum nfs_ftype4 type, specdata4 *devdata)
{
	struct nfs_inode *ino = inode_new();
	if (!ino)
		return NULL;

	ino->type = type;
	memcpy(&ino->u.devdata, devdata, sizeof(specdata4));

	return ino;
}

static struct nfs_inode *inode_new_symlink(gchar *linktext)
{
	struct nfs_inode *ino = inode_new();
	if (!ino)
		return NULL;

	ino->type = NF4LNK;
	ino->u.linktext = linktext;

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
	case NF4DIR:
		g_assert(ino->u.dir != NULL);
		g_hash_table_destroy(ino->u.dir);
		break;
	case NF4LNK:
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

bool_t nfs_op_create(struct nfs_client *cli, CREATE4args *arg, COMPOUND4res *cres)
{
	struct nfs_resop4 resop;
	CREATE4res *res;
	CREATE4resok *resok;
	nfsstat4 status = NFS4_OK;
	struct nfs_inode *dir_ino, *new_ino;
	struct nfs_fattr_set fattr;

	memset(&resop, 0, sizeof(resop));
	resop.resop = OP_CREATE;
	res = &resop.nfs_resop4_u.opcreate;
	resok = &res->CREATE4res_u.resok4;

	if (!fattr_parse(&arg->createattrs, &fattr)) {
		status = NFS4ERR_INVAL;
		goto out;
	}

	dir_ino = inode_get(cli->current_fh);
	if (!dir_ino) {
		status = NFS4ERR_NOFILEHANDLE;
		goto out;
	}
	if (dir_ino->type != NF4DIR) {
		status = NFS4ERR_NOTDIR;
		goto out;
	}

	switch(arg->objtype.type) {
	case NF4DIR:
		new_ino = inode_new_dir();
		break;
	case NF4BLK:
	case NF4CHR:
		new_ino = inode_new_dev(arg->objtype.type,
				        &arg->objtype.createtype4_u.devdata);
		break;
	case NF4LNK: {
		gchar *linktext =
			copy_utf8string(&arg->objtype.createtype4_u.linkdata);
		if (!linktext) {
			status = NFS4ERR_RESOURCE;
			goto out;
		}
		new_ino = inode_new_symlink(linktext);
		if (!new_ino)
			g_free(linktext);
		break;
	}
	case NF4SOCK:
	case NF4FIFO:
		new_ino = inode_new();
		break;
	default:
		status = NFS4ERR_INVAL;
		goto out;
	}

	if (!new_ino) {
		status = NFS4ERR_RESOURCE;
		goto out;
	}

	resok->cinfo.atomic = TRUE;
	resok->cinfo.before =
	resok->cinfo.after = dir_ino->version;

	status = dir_add(dir_ino, &arg->objname, new_ino->ino);
	if (status != NFS4_OK) {
		inode_free(new_ino);
		goto out;
	}

	g_array_append_val(new_ino->parents, dir_ino->ino);
	resok->cinfo.after = dir_ino->version;
	cli->current_fh = new_ino->ino;

	/* FIXME: attr-on-create */

out:
	res->status = status;
	return push_resop(cres, &resop, status);
}

