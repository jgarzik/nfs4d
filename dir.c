
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

	ino = inode_get(cli->current_fh);
	if (!ino) {
		status = NFS4ERR_NOFILEHANDLE;
		goto out;
	}
	if (ino->type != NF4DIR) {
		if (ino->type == NF4LNK)
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

	ino = inode_get(cli->current_fh);
	if (!ino) {
		status = NFS4ERR_NOFILEHANDLE;
		goto out;
	}
	if (ino->type != NF4DIR) {
		if (ino->type == NF4LNK)
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

void dirent_free(gpointer p)
{
	struct nfs_dirent *dirent = p;

	g_slice_free(struct nfs_dirent, dirent);
}

enum nfsstat4 dir_add(struct nfs_inode *dir_ino, utf8string *name_in,
		      nfsino_t inum)
{
	struct nfs_dirent *dirent;
	gchar *name;
	enum nfsstat4 status = NFS4_OK;

	if (dir_ino->type != NF4DIR)
		return NFS4ERR_NOTDIR;
	if (!valid_utf8string(name_in))
		return NFS4ERR_INVAL;
	if (has_dots(name_in))
		return NFS4ERR_BADNAME;

	g_assert(dir_ino->u.dir != NULL);

	name = copy_utf8string(name_in);
	if (!name)
		return NFS4ERR_RESOURCE;

	dirent = g_hash_table_lookup(dir_ino->u.dir, name);
	if (dirent) {
		status = NFS4ERR_EXIST;
		goto out_name;
	}

	dirent = g_slice_new(struct nfs_dirent);
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

	dir_ino = inode_get(cli->current_fh);
	if (!dir_ino) {
		status = NFS4ERR_NOFILEHANDLE;
		goto out;
	}

	src_ino = inode_get(cli->save_fh);
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

	g_array_append_val(src_ino->parents, dir_ino->ino);

	resok->cinfo.after = dir_ino->version;

out:
	res->status = status;
	return push_resop(cres, &resop, status);
}

bool_t nfs_op_remove(struct nfs_client *cli, REMOVE4args *arg, COMPOUND4res *cres)
{
	struct nfs_resop4 resop;
	REMOVE4res *res;
	REMOVE4resok *resok;
	nfsstat4 status = NFS4_OK;
	struct nfs_inode *dir_ino, *target_ino;
	struct nfs_dirent *dirent;
	gchar *name;

	memset(&resop, 0, sizeof(resop));
	resop.resop = OP_REMOVE;
	res = &resop.nfs_resop4_u.opremove;
	resok = &res->REMOVE4res_u.resok4;

	if (!valid_utf8string(&arg->target)) {
		status = NFS4ERR_INVAL;
		goto out;
	}

	/* reference container directory */
	dir_ino = inode_get(cli->current_fh);
	if (!dir_ino) {
		status = NFS4ERR_NOFILEHANDLE;
		goto out;
	}
	if (dir_ino->type != NF4DIR) {
		status = NFS4ERR_NOTDIR;
		goto out;
	}

	/* copy target name */
	name = copy_utf8string(&arg->target);
	if (!name) {
		status = NFS4ERR_RESOURCE;
		goto out;
	}

	/* lookup target name in directory */
	dirent = g_hash_table_lookup(dir_ino->u.dir, name);
	if (!dirent) {
		status = NFS4ERR_NOENT;
		goto out_name;
	}

	/* reference target inode */
	target_ino = inode_get(dirent->ino);
	if (!target_ino) {			/* should never happen */
		status = NFS4ERR_SERVERFAULT;
		goto out_name;
	}

	/* prevent removal of non-empty dirs */
	if ((target_ino->type == NF4DIR) &&
	    (g_hash_table_size(target_ino->u.dir) > 0)) {
		status = NFS4ERR_INVAL;
		goto out_name;
	}

	/* prevent root dir deletion */
	if (target_ino->ino == INO_ROOT) {
		status = NFS4ERR_INVAL;
		goto out_name;
	}

	/* remove target inode from directory */
	g_hash_table_remove(dir_ino->u.dir, name);

	/* record directory change info */
	resok->cinfo.atomic = TRUE;
	resok->cinfo.before = dir_ino->version;
	inode_touch(dir_ino);
	resok->cinfo.after = dir_ino->version;

	/* remove link, possibly deleting inode */
	inode_unlink(target_ino, dir_ino->ino);

out_name:
	g_free(name);
out:
	res->status = status;
	return push_resop(cres, &resop, status);
}

bool_t nfs_op_rename(struct nfs_client *cli, RENAME4args *arg, COMPOUND4res *cres)
{
	struct nfs_resop4 resop;
	RENAME4res *res;
	RENAME4resok *resok;
	nfsstat4 status = NFS4_OK;
	struct nfs_inode *src_dir, *target_dir;
	struct nfs_inode *old_file;
	struct nfs_dirent *old_dirent, *new_dirent;
	gchar *old_name, *new_name;

	memset(&resop, 0, sizeof(resop));
	resop.resop = OP_RENAME;
	res = &resop.nfs_resop4_u.oprename;
	resok = &res->RENAME4res_u.resok4;

	/* validate text input */
	if ((!valid_utf8string(&arg->oldname)) ||
	    (!valid_utf8string(&arg->newname))) {
		status = NFS4ERR_INVAL;
		goto out;
	}
	if (has_dots(&arg->oldname) || has_dots(&arg->newname)) {
		status = NFS4ERR_BADNAME;
		goto out;
	}

	/* reference source, target directories.
	 * NOTE: src_dir and target_dir may point to the same object
	 */
	src_dir = inode_get(cli->save_fh);
	target_dir = inode_get(cli->current_fh);
	if (!src_dir || !target_dir) {
		status = NFS4ERR_NOFILEHANDLE;
		goto out;
	}
	if ((src_dir->type != NF4DIR) || (target_dir->type != NF4DIR)) {
		status = NFS4ERR_NOTDIR;
		goto out;
	}

	/* copy source, target names */
	old_name = copy_utf8string(&arg->oldname);
	new_name = copy_utf8string(&arg->newname);
	if (!old_name || !new_name) {
		status = NFS4ERR_RESOURCE;
		goto out_name;
	}

	/* lookup source, target names */
	old_dirent = g_hash_table_lookup(src_dir->u.dir, old_name);
	if (!old_dirent) {
		status = NFS4ERR_NOENT;
		goto out_name;
	}
	old_file = inode_get(old_dirent->ino);
	if (!old_file) {			/* should never happen */
		status = NFS4ERR_SERVERFAULT;
		goto out_name;
	}
	new_dirent = g_hash_table_lookup(target_dir->u.dir, new_name);

	/* if target (newname) is present, attempt to remove */
	if (new_dirent != NULL) {
		gboolean ok_to_remove = FALSE;
		struct nfs_inode *new_file;

		new_file = inode_get(new_dirent->ino);
		if (!new_file) {		/* should never happen */
			status = NFS4ERR_SERVERFAULT;
			goto out_name;
		}

		/* do oldname and newname refer to same file? */
		if (old_file->ino == new_file->ino) {
			resok->source_cinfo.atomic = TRUE;
			resok->source_cinfo.after =
			resok->source_cinfo.before = src_dir->version;
			resok->target_cinfo.atomic = TRUE;
			resok->target_cinfo.after =
			resok->target_cinfo.before = target_dir->version;
			goto out_name;
		}

		if (old_file->type == NF4DIR && new_file->type == NF4DIR) {
			if (g_hash_table_size(new_file->u.dir) == 0)
				ok_to_remove = TRUE;
		}
		else if (old_file->type != NF4DIR && new_file->type != NF4DIR) {
			ok_to_remove = TRUE;
		}

		if (ok_to_remove) {
			/* remove target inode from directory */
			g_hash_table_remove(target_dir->u.dir, new_name);

			/* remove link, possibly deleting inode */
			inode_unlink(new_file, target_dir->ino);
		} else {
			status = NFS4ERR_EXIST;
			goto out_name;
		}
	}

	new_dirent = g_slice_new(struct nfs_dirent);
	if (!new_dirent) {
		status = NFS4ERR_RESOURCE;
		goto out_name;
	}
	new_dirent->ino = old_dirent->ino;

	g_hash_table_remove(src_dir->u.dir, old_name);
	g_hash_table_insert(target_dir->u.dir, new_name, new_dirent);
	new_name = NULL;	/* prevent function exit from freeing */

	/* record directory change info */
	resok->source_cinfo.atomic = TRUE;
	resok->source_cinfo.before = src_dir->version;
	resok->target_cinfo.atomic = TRUE;
	resok->target_cinfo.before = target_dir->version;

	inode_touch(src_dir);
	if (src_dir != target_dir)
		inode_touch(target_dir);

	resok->source_cinfo.after = src_dir->version;
	resok->target_cinfo.after = target_dir->version;

out_name:
	g_free(old_name);
	g_free(new_name);
out:
	res->status = status;
	return push_resop(cres, &resop, status);
}

