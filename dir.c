
#include <string.h>
#include <glib.h>
#include "server.h"
#include "nfs4_prot.h"

bool_t nfs_op_lookup(struct nfs_client *cli, LOOKUP4args *arg, COMPOUND4res *cres)
{
	struct nfs_resop4 resop;
	LOOKUP4res *res;
	nfsstat4 status = NFS4_OK;
	struct nfs_inode *ino;
	struct nfs_dirent *dirent;
	gchar *name;

	memset(&resop, 0, sizeof(resop));
	resop.resop = OP_LOOKUP;
	res = &resop.nfs_resop4_u.oplookup;

	if (!valid_utf8string(&arg->objname)) {
		status = NFS4ERR_INVAL;
		goto out;
	}

	ino = ino_get(cli->current_fh);
	if (!ino) {
		status = NFS4ERR_NOFILEHANDLE;
		goto out;
	}
	if (ino->type != IT_DIR) {
		if (ino->type == IT_SYMLINK)
			status = NFS4ERR_SYMLINK;
		else
			status = NFS4ERR_NOTDIR;
		goto out;
	}

	name = copy_utf8string(&arg->objname);
	if (!name) {
		status = NFS4ERR_RESOURCE;
		goto out;
	}

	g_assert(ino->u.dir != NULL);

	dirent = g_hash_table_lookup(ino->u.dir, name);
	if (!dirent) {
		status = NFS4ERR_NOENT;
		goto out_name;
	}

	cli->current_fh = dirent->ino;

out_name:
	g_free(name);
out:
	res->status = status;
	return push_resop(cres, &resop, status);
}

bool_t nfs_op_lookupp(struct nfs_client *cli, COMPOUND4res *cres)
{
	struct nfs_resop4 resop;
	LOOKUPP4res *res;
	nfsstat4 status = NFS4_OK;
	struct nfs_inode *ino;

	memset(&resop, 0, sizeof(resop));
	resop.resop = OP_LOOKUPP;
	res = &resop.nfs_resop4_u.oplookupp;

	ino = ino_get(cli->current_fh);
	if (!ino) {
		status = NFS4ERR_NOFILEHANDLE;
		goto out;
	}
	if (ino->type != IT_DIR) {
		if (ino->type == IT_SYMLINK)
			status = NFS4ERR_SYMLINK;
		else
			status = NFS4ERR_NOTDIR;
		goto out;
	}

	if (ino->parents->len == 0) {	/* root inode, no parents */
		status = NFS4ERR_NOENT;
		goto out;
	}

	cli->current_fh = g_array_index(ino->parents, nfsino_t, 0);

out:
	res->status = status;
	return push_resop(cres, &resop, status);
}

static enum nfsstat4 dir_add(struct nfs_inode *dir_ino, utf8string *name_in,
			     nfsino_t inum)
{
	struct nfs_dirent *dirent;
	gchar *name;
	enum nfsstat4 status = NFS4_OK;

	if (dir_ino->type != IT_DIR)
		return NFS4ERR_NOTDIR;
	if (!valid_utf8string(name_in))
		return NFS4ERR_INVAL;
	if (has_dots(name_in))
		return NFS4ERR_INVAL;

	g_assert(dir_ino->u.dir != NULL);

	name = copy_utf8string(name_in);
	if (!name)
		return NFS4ERR_RESOURCE;

	dirent = g_hash_table_lookup(dir_ino->u.dir, name);
	if (dirent) {
		status = NFS4ERR_EXIST;
		goto out_name;
	}

	dirent = g_new(struct nfs_dirent, 1);
	if (!dirent) {
		status = NFS4ERR_RESOURCE;
		goto out_name;
	}
	dirent->ino = inum;

	g_hash_table_insert(dir_ino->u.dir, name, dirent);
	inode_touch(dir_ino);

	goto out;

out_name:
	g_free(name);
out:
	return status;
}

bool_t nfs_op_link(struct nfs_client *cli, LINK4args *arg, COMPOUND4res *cres)
{
	struct nfs_resop4 resop;
	LINK4res *res;
	LINK4resok *resok;
	nfsstat4 status;
	struct nfs_inode *dir_ino, *src_ino;

	memset(&resop, 0, sizeof(resop));
	resop.resop = OP_LINK;
	res = &resop.nfs_resop4_u.oplink;
	resok = &res->LINK4res_u.resok4;

	if (cli->current_fh == cli->save_fh) {
		status = NFS4ERR_INVAL;
		goto out;
	}

	dir_ino = ino_get(cli->current_fh);
	if (!dir_ino) {
		status = NFS4ERR_NOFILEHANDLE;
		goto out;
	}

	src_ino = ino_get(cli->save_fh);
	if (!src_ino) {
		status = NFS4ERR_NOFILEHANDLE;
		goto out;
	}

	resok->cinfo.atomic = TRUE;
	resok->cinfo.before = 
	resok->cinfo.after = dir_ino->version;

	status = dir_add(dir_ino, &arg->newname, cli->save_fh);
	if (status != NFS4_OK)
		goto out;

	resok->cinfo.after = dir_ino->version;

out:
	res->status = status;
	return push_resop(cres, &resop, status);
}

