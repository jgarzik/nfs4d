
#define _GNU_SOURCE
#include <string.h>
#include <glib.h>
#include <syslog.h>
#include <string.h>
#include "server.h"
#include "nfs4_prot.h"

static bool has_slash(const struct nfs_buf *str)
{
	if (!str)
		return false;
	if (g_utf8_strchr(str->val, str->len, '/'))
		return true;
	return false;
}

static bool has_dots(const struct nfs_buf *str)
{
	if (!str)
		return false;
	if ((str->len == 1) &&
	    (!memcmp(str->val, ".", 1)))
		return true;
	if ((str->len == 2) &&
	    (!memcmp(str->val, "..", 2)))
		return true;
	return false;
}

nfsstat4 dir_curfh(const struct nfs_cxn *cxn, struct nfs_inode **ino_out)
{
	nfsstat4 status;
	struct nfs_inode *ino;

	*ino_out = NULL;
	status = NFS4_OK;
	ino = inode_get(cxn->current_fh);
	if (!ino) {
		status = NFS4ERR_NOFILEHANDLE;
		goto out;
	}

	*ino_out = ino;
	if (ino->type != NF4DIR) {
		/* NOTE: add NF4LNK tests at caller */
		status = NFS4ERR_NOTDIR;
	}

out:
	return status;
}

nfsstat4 dir_lookup(struct nfs_inode *dir_ino, const struct nfs_buf *str,
		    struct nfs_dirent **dirent_out)
{
	struct nfs_dirent *dirent;
	char *name;

	if (dirent_out)
		*dirent_out = NULL;

	if (!dir_ino->mode)
		return NFS4ERR_ACCESS;
	if (dir_ino->type != NF4DIR) {
		if (dir_ino->type == NF4LNK)
			return NFS4ERR_SYMLINK;
		return NFS4ERR_NOTDIR;
	}
	if (!valid_utf8string(str))
		return NFS4ERR_INVAL;
	if (has_dots(str))
		return NFS4ERR_BADNAME;
	if (has_slash(str))
		return NFS4ERR_BADNAME;

	name = copy_utf8string(str);
	if (!name)
		return NFS4ERR_RESOURCE;

	g_assert(dir_ino->u.dir != NULL);

	dirent = g_tree_lookup(dir_ino->u.dir, name);

	free(name);

	if (!dirent)
		return NFS4ERR_NOENT;

	if (dirent_out)
		*dirent_out = dirent;
	return NFS4_OK;
}

nfsstat4 nfs_op_lookup(struct nfs_cxn *cxn, struct curbuf *cur,
		       struct list_head *writes, struct rpc_write **wr)
{
	nfsstat4 status = NFS4_OK;
	struct nfs_inode *ino;
	struct nfs_dirent *dirent;
	bool printed = false;
	struct nfs_buf objname;

	CURBUF(&objname);

	if (!objname.len) {
		status = NFS4ERR_INVAL;
		goto out;
	}
	if (!objname.val) {
		status = NFS4ERR_BADXDR;
		goto out;
	}

	if (objname.len > SRV_MAX_NAME) {
		status = NFS4ERR_NAMETOOLONG;
		goto out;
	}

	status = dir_curfh(cxn, &ino);
	if (status != NFS4_OK) {
		if ((status == NFS4ERR_NOTDIR) &&
		    (ino->type == NF4LNK))
			status = NFS4ERR_SYMLINK;
		goto out;
	}

	status = dir_lookup(ino, &objname, &dirent);
	if (status != NFS4_OK)
		goto out;

	cxn->current_fh = dirent->ino;

	if (debugging) {
		syslog(LOG_INFO, "op LOOKUP ('%.*s') -> %u",
		       objname.len,
		       objname.val,
		       cxn->current_fh);
		printed = true;
	}

out:
	if (!printed) {
		if (debugging)
			syslog(LOG_INFO, "op LOOKUP ('%.*s')",
			       objname.len,
			       objname.val);
	}

	WR32(status);
	return status;
}

nfsstat4 nfs_op_lookupp(struct nfs_cxn *cxn, struct curbuf *cur,
		       struct list_head *writes, struct rpc_write **wr)
{
	nfsstat4 status = NFS4_OK;
	struct nfs_inode *ino;

	if (debugging)
		syslog(LOG_INFO, "op LOOKUPP");

	status = dir_curfh(cxn, &ino);
	if (status != NFS4_OK)
		goto out;

	if (ino->parents->len == 0) {	/* root inode, no parents */
		status = NFS4ERR_NOENT;
		goto out;
	}

	cxn->current_fh = g_array_index(ino->parents, nfsino_t, 0);

out:
	WR32(status);
	return status;
}

void dirent_free(gpointer p)
{
	struct nfs_dirent *dirent = p;

	if (!dirent)
		return;

	memset(dirent, 0, sizeof(*dirent));

	free(dirent);
}

enum nfsstat4 dir_add(struct nfs_inode *dir_ino, const struct nfs_buf *name_in,
		      nfsino_t inum)
{
	struct nfs_dirent *dirent;
	char *name;
	enum nfsstat4 status = NFS4_OK, lu_stat;

	lu_stat = dir_lookup(dir_ino, name_in, NULL);
	if (lu_stat != NFS4ERR_NOENT) {
		if (lu_stat == NFS4_OK)
			status = NFS4ERR_EXIST;
		else
			status = lu_stat;
		return status;
	}

	name = copy_utf8string(name_in);
	if (!name)
		return NFS4ERR_RESOURCE;

	dirent = calloc(1, sizeof(struct nfs_dirent));
	if (!dirent) {
		status = NFS4ERR_RESOURCE;
		goto out_name;
	}
	dirent->ino = inum;

	g_tree_insert(dir_ino->u.dir, name, dirent);
	inode_touch(dir_ino);

	goto out;

out_name:
	free(name);
out:
	return status;
}

nfsstat4 nfs_op_link(struct nfs_cxn *cxn, struct curbuf *cur,
		     struct list_head *writes, struct rpc_write **wr)
{
	nfsstat4 status;
	struct nfs_inode *dir_ino, *src_ino;
	struct nfs_buf newname;
	uint64_t before, after;

	CURBUF(&newname);

	if (debugging)
		syslog(LOG_INFO, "op LINK (%.*s)",
		       newname.len,
		       newname.val);

	if (!cxn->current_fh || !cxn->save_fh) {
		status = NFS4ERR_NOFILEHANDLE;
		goto out;
	}
	if (newname.len > SRV_MAX_NAME) {
		status = NFS4ERR_NAMETOOLONG;
		goto out;
	}

	dir_ino = inode_get(cxn->current_fh);
	if (!dir_ino) {
		status = NFS4ERR_NOFILEHANDLE;
		goto out;
	}

	/* make sure target is a directory */
	if (dir_ino->type != NF4DIR) {
		status = NFS4ERR_NOTDIR;
		goto out;
	}

	src_ino = inode_get(cxn->save_fh);
	if (!src_ino) {
		status = NFS4ERR_NOFILEHANDLE;
		goto out;
	}

	/* make sure source is -not- a directory */
	if (src_ino->type == NF4DIR) {
		status = NFS4ERR_ISDIR;
		goto out;
	}

	before = dir_ino->version;

	status = dir_add(dir_ino, &newname, cxn->save_fh);
	if (status != NFS4_OK)
		goto out;

	g_array_append_val(src_ino->parents, dir_ino->ino);

	after = dir_ino->version;

out:
	WR32(status);
	if (status == NFS4_OK) {
		WR32(1);		/* cinfo.atomic */
		WR64(before);		/* cinfo.before */
		WR64(after);		/* cinfo.after */
	}
	return status;
}

nfsstat4 nfs_op_remove(struct nfs_cxn *cxn, struct curbuf *cur,
		       struct list_head *writes, struct rpc_write **wr)
{
	nfsstat4 status = NFS4_OK;
	struct nfs_inode *dir_ino, *target_ino;
	struct nfs_dirent *dirent;
	char *name;
	struct nfs_buf target;
	change_info4 cinfo = { true, 0, 0 };

	CURBUF(&target);

	if (debugging)
		syslog(LOG_INFO, "op REMOVE ('%.*s')",
		       target.len,
		       target.val);

	if (target.len > SRV_MAX_NAME) {
		status = NFS4ERR_NAMETOOLONG;
		goto out;
	}

	if (!valid_utf8string(&target)) {
		status = NFS4ERR_INVAL;
		goto out;
	}
	if (has_dots(&target)) {
		status = NFS4ERR_BADNAME;
		goto out;
	}

	/* reference container directory */
	status = dir_curfh(cxn, &dir_ino);
	if (status != NFS4_OK)
		goto out;

	/* copy target name */
	name = copy_utf8string(&target);
	if (!name) {
		status = NFS4ERR_RESOURCE;
		goto out;
	}

	/* lookup target name in directory */
	dirent = g_tree_lookup(dir_ino->u.dir, name);
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
	    (g_tree_nnodes(target_ino->u.dir) > 0)) {
		status = NFS4ERR_NOTEMPTY;
		goto out_name;
	}

	/* prevent root dir deletion */
	if (target_ino->ino == INO_ROOT) {
		status = NFS4ERR_INVAL;
		goto out_name;
	}

	/* remove target inode from directory */
	g_tree_remove(dir_ino->u.dir, name);

	/* record directory change info */
	cinfo.before = dir_ino->version;
	inode_touch(dir_ino);
	cinfo.after = dir_ino->version;

	/* remove link, possibly deleting inode */
	inode_unlink(target_ino, dir_ino->ino);

out_name:
	free(name);
out:
	WR32(status);
	if (status == NFS4_OK) {
		WR32(cinfo.atomic ? 1 : 0);	/* cinfo.atomic */
		WR64(cinfo.before);		/* cinfo.before */
		WR64(cinfo.after);		/* cinfo.after */
	}
	return status;
}

nfsstat4 nfs_op_rename(struct nfs_cxn *cxn, struct curbuf *cur,
		       struct list_head *writes, struct rpc_write **wr)
{
	nfsstat4 status = NFS4_OK;
	struct nfs_inode *src_dir, *target_dir;
	struct nfs_inode *old_file;
	struct nfs_dirent *old_dirent, *new_dirent;
	char *old_name, *new_name;
	struct nfs_buf oldname, newname;
	change_info4 src = { true, 0, 0 };
	change_info4 target = { true, 0, 0 };

	CURBUF(&oldname);
	CURBUF(&newname);

	if (debugging)
		syslog(LOG_INFO, "op REMOVE (OLD:%.*s, NEW:%.*s)",
		       oldname.len,
		       oldname.val,
		       newname.len,
		       newname.val);

	/* validate text input */
	if ((!valid_utf8string(&oldname)) ||
	    (!valid_utf8string(&newname))) {
		status = NFS4ERR_INVAL;
		goto out;
	}
	if (has_dots(&oldname) || has_dots(&newname)) {
		status = NFS4ERR_BADNAME;
		goto out;
	}

	/* reference source, target directories.
	 * NOTE: src_dir and target_dir may point to the same object
	 */
	src_dir = inode_get(cxn->save_fh);
	target_dir = inode_get(cxn->current_fh);
	if (!src_dir || !target_dir) {
		status = NFS4ERR_NOFILEHANDLE;
		goto out;
	}
	if ((src_dir->type != NF4DIR) || (target_dir->type != NF4DIR)) {
		status = NFS4ERR_NOTDIR;
		goto out;
	}

	/* copy source, target names */
	old_name = copy_utf8string(&oldname);
	new_name = copy_utf8string(&newname);
	if (!old_name || !new_name) {
		status = NFS4ERR_RESOURCE;
		goto out_name;
	}

	/* lookup source, target names */
	old_dirent = g_tree_lookup(src_dir->u.dir, old_name);
	if (!old_dirent) {
		status = NFS4ERR_NOENT;
		goto out_name;
	}
	old_file = inode_get(old_dirent->ino);
	if (!old_file) {			/* should never happen */
		status = NFS4ERR_SERVERFAULT;
		goto out_name;
	}
	new_dirent = g_tree_lookup(target_dir->u.dir, new_name);

	/* if target (newname) is present, attempt to remove */
	if (new_dirent != NULL) {
		bool ok_to_remove = false;
		struct nfs_inode *new_file;

		new_file = inode_get(new_dirent->ino);
		if (!new_file) {		/* should never happen */
			status = NFS4ERR_SERVERFAULT;
			goto out_name;
		}

		/* do oldname and newname refer to same file? */
		if (old_file->ino == new_file->ino) {
			src.after =
			src.before = src_dir->version;
			target.after =
			target.before = target_dir->version;
			goto out_name;
		}

		if (old_file->type == NF4DIR && new_file->type == NF4DIR) {
			if (g_tree_nnodes(new_file->u.dir) == 0)
				ok_to_remove = true;
		}
		else if (old_file->type != NF4DIR && new_file->type != NF4DIR) {
			ok_to_remove = true;
		}

		if (ok_to_remove) {
			/* remove target inode from directory */
			g_tree_remove(target_dir->u.dir, new_name);

			/* remove link, possibly deleting inode */
			inode_unlink(new_file, target_dir->ino);
		} else {
			status = NFS4ERR_EXIST;
			goto out_name;
		}
	}

	new_dirent = calloc(1, sizeof(struct nfs_dirent));
	if (!new_dirent) {
		status = NFS4ERR_RESOURCE;
		goto out_name;
	}
	new_dirent->ino = old_dirent->ino;

	g_tree_remove(src_dir->u.dir, old_name);
	g_tree_insert(target_dir->u.dir, new_name, new_dirent);
	new_name = NULL;	/* prevent function exit from freeing */

	/* record directory change info */
	src.before = src_dir->version;
	target.before = target_dir->version;

	inode_touch(src_dir);
	if (src_dir != target_dir)
		inode_touch(target_dir);

	src.after = src_dir->version;
	target.after = target_dir->version;

out_name:
	free(old_name);
	free(new_name);
out:
	WR32(status);
	if (status == NFS4_OK) {
		WR32(src.atomic ? 1 : 0); /* src cinfo.atomic */
		WR64(src.before);	/* src cinfo.before */
		WR64(src.after);	/* src cinfo.after */
		WR32(target.atomic ? 1 : 0); /* target cinfo.atomic */
		WR64(target.before);	/* target cinfo.before */
		WR64(target.after);	/* target cinfo.after */
	}
	return status;
}

struct readdir_info {
	uint64_t cookie;
	uint32_t dircount;
	uint32_t maxcount;
	uint64_t attr_request;

	uint32_t dir_pos;

	struct list_head *writes;
	struct rpc_write **wr;

	uint32_t *val_follows;

	nfsstat4 status;

	bool cookie_found;
	bool stop;
	bool hit_limit;
	bool first_time;

	unsigned int n_results;
};

static gboolean readdir_iter(gpointer key, gpointer value, gpointer user_data)
{
	char *name = key;
	size_t name_len = strlen(name);
	uint64_t bitmap_out = 0;
	struct nfs_dirent *de = value;
	struct readdir_info *ri = user_data;
	uint32_t dirlen, maxlen;
	struct nfs_fattr_set attr;
	struct nfs_buf nb;
	struct nfs_inode *ino;
	struct list_head *writes = ri->writes;
	struct rpc_write **wr = ri->wr;

	if (ri->stop)
		return TRUE;

	if (!ri->cookie_found) {
		if (ri->cookie && (ri->dir_pos <= ri->cookie)) {
			ri->dir_pos++;
			return FALSE;
		}
		ri->cookie_found = true;
	}

	ino = inode_get(de->ino);
	if (!ino) {
		/* FIXME: return via rdattr-error */
		ri->stop = true;
		ri->status = NFS4ERR_SERVERFAULT;
		return TRUE;
	}

	memset(&attr, 0, sizeof(attr));

	fattr_fill(ino, &attr);

	dirlen = 8 + 4 + (XDR_QUADLEN(name_len) * 4);
	if (dirlen > ri->dircount) {
		ri->hit_limit = true;
		ri->stop = true;
		goto out;
	}

	maxlen = 8 + 4 + (XDR_QUADLEN(name_len) * 4) +
		 16 + fattr_size(&attr) + 4;
	if (maxlen > ri->maxcount) {
		ri->hit_limit = true;
		ri->stop = true;
		goto out;
	}

	if (ri->first_time) {
		ri->first_time = false;

		/* FIXME: server verifier isn't the best for dir verf */
		WRMEM(&srv.instance_verf, sizeof(verifier4));	/* cookieverf */

		ri->val_follows = WRSKIP(4);
	}

	ri->dircount -= dirlen;
	ri->maxcount -= maxlen;

	/* write value to previous entry4.nextentry */
	*ri->val_follows = htonl(1);
	ri->val_follows = NULL;

	WR64(ri->dir_pos);		/* entry4.cookie */

	nb.len = name_len;		/* entry4.name */
	nb.val = name;
	WRBUF(&nb);

	/* entry4.attrs */
	attr.bitmap = ri->attr_request;
	ri->status = wr_fattr(&attr, &bitmap_out, writes, wr);
	if (ri->status != NFS4_OK)
		ri->stop = true;

	if (debugging)
		syslog(LOG_DEBUG, "   READDIR ent: '%s' (MAP:%Lx WRLEN:%u)",
			name, (unsigned long long) bitmap_out, (*wr)->len);

	ri->val_follows = WRSKIP(4);	/* entry4.nextentry */

	ri->n_results++;
	ri->dir_pos++;

out:
	fattr_free(&attr);
	if (ri->stop)
		return TRUE;
	return FALSE;
}

nfsstat4 nfs_op_readdir(struct nfs_cxn *cxn, struct curbuf *cur,
		        struct list_head *writes, struct rpc_write **wr)
{
	nfsstat4 status = NFS4_OK;
	struct nfs_inode *ino;
	uint32_t dircount, maxcount, *status_p;
	struct readdir_info ri;
	uint64_t cookie, attr_request;
	verifier4 *cookie_verf;

	cookie = CR64();
	cookie_verf = CURMEM(sizeof(verifier4));
	dircount = CR32();
	maxcount = CR32();
	attr_request = CURMAP();

	status_p = WRSKIP(4);

	if (debugging) {
		syslog(LOG_INFO, "op READDIR (COOKIE:%Lu DIR:%u MAX:%u MAP:%Lx)",
		       (unsigned long long) cookie,
		       dircount,
		       maxcount,
		       (unsigned long long) attr_request);

		print_fattr_bitmap("op READDIR", attr_request);
	}

	if (cookie == 1 || cookie == 2) {
		status = NFS4ERR_BAD_COOKIE;
		goto out;
	}
	if (attr_request & fattr_write_only_mask) {
		status = NFS4ERR_INVAL;
		goto out;
	}

	/* FIXME: very, very, very poor verifier */
	if (cookie &&
	    memcmp(cookie_verf, &srv.instance_verf, sizeof(verifier4))) {
		status = NFS4ERR_NOT_SAME;
		goto out;
	}

	status = dir_curfh(cxn, &ino);
	if (status != NFS4_OK)
		goto out;
	if (ino->mode == 0) {
		status = NFS4ERR_ACCESS;
		goto out;
	}

	/* subtract READDIR4resok header and footer size */
	if (maxcount < 16) {
		status = NFS4ERR_TOOSMALL;
		goto out;
	}

	maxcount -= (8 + 4 + 4);

	if (dircount > SRV_MAX_READ || maxcount > SRV_MAX_READ) {
		status = NFS4ERR_INVAL;
		goto out;
	}

	memset(&ri, 0, sizeof(ri));
	ri.cookie = cookie;
	ri.dircount = dircount;
	ri.maxcount = maxcount;
	ri.attr_request = attr_request;
	ri.status = NFS4_OK;
	ri.writes = writes;
	ri.wr = wr;
	ri.dir_pos = 3;
	ri.first_time = true;

	if (g_tree_nnodes(ino->u.dir) == 0) {
		WRMEM(&srv.instance_verf, sizeof(verifier4));	/* cookieverf */

		ri.val_follows = WRSKIP(4);
	} else {
		g_tree_foreach(ino->u.dir, readdir_iter, &ri);
	}

	/* terminate final entry4.nextentry and dirlist4.entries */
	if (ri.val_follows)
		*ri.val_follows = htonl(0);

	if (ri.cookie_found && !ri.n_results && ri.hit_limit) {
		status = NFS4ERR_TOOSMALL;
		goto out;
	}

	WR32(ri.hit_limit ? 0 : 1);		/* reply eof */

out:
	*status_p = htonl(status);
	return status;
}

