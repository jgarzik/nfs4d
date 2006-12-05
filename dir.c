
#include <string.h>
#include <glib.h>
#include "server.h"
#include "nfs4_prot.h"

nfsstat4 dir_curfh(const struct nfs_client *cli, struct nfs_inode **ino_out)
{
	nfsstat4 status;
	struct nfs_inode *ino;

	*ino_out = NULL;
	status = NFS4_OK;
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

	*ino_out = ino;

out:
	return status;
}

nfsstat4 dir_lookup(struct nfs_inode *dir_ino, utf8string *str,
		    struct nfs_dirent **dirent_out)
{
	struct nfs_dirent *dirent;
	gchar *name;

	if (dirent_out)
		*dirent_out = NULL;

	if (dir_ino->type != NF4DIR)
		return NFS4ERR_NOTDIR;
	if (!valid_utf8string(str))
		return NFS4ERR_INVAL;
	if (has_dots(str))
		return NFS4ERR_BADNAME;

	name = copy_utf8string(str);
	if (!name)
		return NFS4ERR_RESOURCE;

	g_assert(dir_ino->u.dir != NULL);

	dirent = g_hash_table_lookup(dir_ino->u.dir, name);

	g_free(name);

	if (!dirent)
		return NFS4ERR_NOENT;

	if (dirent_out)
		*dirent_out = dirent;
	return NFS4_OK;
}

bool_t nfs_op_lookup(struct nfs_client *cli, LOOKUP4args *arg, COMPOUND4res *cres)
{
	struct nfs_resop4 resop;
	LOOKUP4res *res;
	nfsstat4 status = NFS4_OK;
	struct nfs_inode *ino;
	struct nfs_dirent *dirent;

	memset(&resop, 0, sizeof(resop));
	resop.resop = OP_LOOKUP;
	res = &resop.nfs_resop4_u.oplookup;

	status = dir_curfh(cli, &ino);
	if (status != NFS4_OK)
		goto out;

	status = dir_lookup(ino, &arg->objname, &dirent);
	if (status != NFS4_OK)
		goto out;

	cli->current_fh = dirent->ino;

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

	status = dir_curfh(cli, &ino);
	if (status != NFS4_OK)
		goto out;

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
	enum nfsstat4 status = NFS4_OK, lu_stat;

	lu_stat = dir_lookup(dir_ino, name_in, NULL);
	if (status != NFS4ERR_NOENT) {
		if (status == NFS4_OK)
			status = NFS4ERR_EXIST;
		return status;
	}

	name = copy_utf8string(name_in);
	if (!name)
		return NFS4ERR_RESOURCE;

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
	status = dir_curfh(cli, &dir_ino);
	if (status != NFS4_OK)
		goto out;

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

static void entry4_free(entry4 *ent)
{
	g_free(ent->name.utf8string_val);
	fattr4_free(&ent->attrs);
	g_slice_free(entry4, ent);
}

static nfsstat4 entry4_new(unsigned long hash, const gchar *name,
			   guint64 bitmap, const struct nfs_dirent *de,
			   entry4 **new_entry_out)
{
	nfsstat4 status = NFS4_OK;
	entry4 *ent;
	struct nfs_inode *ino;
	struct nfs_fattr_set attrset;
	bool_t encode_rc;

	ent = g_slice_new0(entry4);
	if (!ent) {
		status = NFS4ERR_RESOURCE;
		goto out;
	}

	ent->cookie = hash;
	ent->name.utf8string_len = strlen(name);
	ent->name.utf8string_val = g_memdup(name, ent->name.utf8string_len);
	if (!ent->name.utf8string_val) {
		status = NFS4ERR_RESOURCE;
		goto err_out;
	}

	memset(&attrset, 0, sizeof(attrset));
	attrset.bitmap = bitmap;

	ino = inode_get(de->ino);
	if (!ino) {
		if (!(bitmap & (1ULL << FATTR4_RDATTR_ERROR))) {
			status = NFS4ERR_NOFILEHANDLE;
			goto err_out_name;
		}
		bitmap = (1ULL << FATTR4_RDATTR_ERROR);
		attrset.rdattr_error = NFS4ERR_NOFILEHANDLE;
	} else
		fattr_fill(ino, &attrset);

	encode_rc = fattr_encode(&ent->attrs, &attrset);
	fattr_free(&attrset);

	if (!encode_rc) {
		status = NFS4ERR_IO;
		goto err_out_name;
	}

out:
	return status;

err_out_name:
	g_free(ent->name.utf8string_val);
err_out:
	g_slice_free(entry4, ent);
	goto out;
}

struct readdir_info {
	unsigned long		hash;
	unsigned long		cookie;
	gboolean		found_cookie;
	gboolean		full;

	guint64			attr_req;

	entry4			*tail;

	nfsstat4		status;
	READDIR4resok		*resok;

	unsigned int		max_dir_sz;
	unsigned int		max_reply_sz;
	unsigned int		dir_sz;
	unsigned int		reply_sz;

	unsigned int		n_entries;
};

static void readdir_iter(gpointer key, gpointer value, gpointer user_data)
{
	gchar *name = key;
	struct nfs_dirent *de = value;
	struct readdir_info *ri = user_data;
	unsigned long hash = blob_hash(ri->hash, name, strlen(name));
	entry4 *new_entry = NULL;
	unsigned int new_dir_sz, new_reply_sz;

	if (ri->status != NFS4_OK)
		return;
	if (ri->full)
		return;

	if (!ri->found_cookie) {
		if (hash != ri->cookie)
			return;
		ri->found_cookie = TRUE;
	}

	ri->status = entry4_new(hash, name, ri->attr_req, de, &new_entry);
	if (ri->status != NFS4_OK)
		return;

	new_dir_sz = sizeof(nfs_cookie4) + sizeof(component4) +
		     new_entry->name.utf8string_len;
	new_reply_sz = sizeof(entry4) + new_entry->name.utf8string_len +
		       new_entry->attrs.attrmask.bitmap4_len +
		       new_entry->attrs.attr_vals.attrlist4_len;

	if (((ri->dir_sz + new_dir_sz) > ri->max_dir_sz) ||
	    ((ri->reply_sz + new_reply_sz) > ri->max_reply_sz)) {
		ri->full = TRUE;
		entry4_free(new_entry);
		return;
	}

	if (!ri->resok->reply.entries)
		ri->resok->reply.entries = new_entry;
	if (ri->tail)
		ri->tail->nextentry = new_entry;
	ri->tail = new_entry;
	ri->n_entries++;
	ri->dir_sz += new_dir_sz;
	ri->reply_sz += new_reply_sz;
}

bool_t nfs_op_readdir(struct nfs_client *cli, READDIR4args *args,
		      COMPOUND4res *cres)
{
	struct nfs_resop4 resop;
	READDIR4res *res;
	READDIR4resok *resok;
	nfsstat4 status = NFS4_OK;
	struct nfs_inode *ino;
	guint32 tmp_ino_n;
	struct readdir_info ri;

	memset(&resop, 0, sizeof(resop));
	resop.resop = OP_READDIR;
	res = &resop.nfs_resop4_u.opreaddir;
	resok = &res->READDIR4res_u.resok4;

	if (args->cookie &&
	    memcmp(&args->cookieverf, &srv.instance_verf, sizeof(verifier4))) {
		status = NFS4ERR_NOT_SAME;
		goto out;
	}

	memset(&ri, 0, sizeof(ri));
	ri.cookie = (unsigned long) args->cookie;
	if (!ri.cookie)
		ri.found_cookie = TRUE;
	ri.attr_req = get_bitmap(&args->attr_request);
	ri.status = NFS4_OK;
	ri.resok = resok;
	ri.max_dir_sz = args->dircount;
	ri.max_reply_sz = args->maxcount;

	status = dir_curfh(cli, &ino);
	if (status != NFS4_OK)
		goto out;

	memcpy(&resok->cookieverf, &srv.instance_verf, sizeof(verifier4));
	resok->reply.eof = TRUE;
	tmp_ino_n = GUINT32_TO_LE(ino->ino);
	ri.hash = blob_hash(BLOB_HASH_INIT, &tmp_ino_n, sizeof(tmp_ino_n));

	g_hash_table_foreach(ino->u.dir, readdir_iter, &ri);

	status = ri.status;
	if (ri.full)
		resok->reply.eof = FALSE;

out:
	res->status = status;
	return push_resop(cres, &resop, status);
}

