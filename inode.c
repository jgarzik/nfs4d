#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <syslog.h>
#include <errno.h>
#include <glib.h>
#include "server.h"
#include "nfs4_prot.h"

nfsino_t next_ino = INO_RESERVED_LAST + 1;

static const struct idmap_ent {
	const char		*name;
	int			id;
} idmap[] = {
	{ "root@localdomain", 0 },
	{ "jgarzik@localdomain", 500 },

	{ }	/* terminate list */
};

static int srv_lookup_user(const utf8string *user)
{
	const struct idmap_ent *ent = &idmap[0];
	size_t len;

	while (ent->name) {
		len = strlen(ent->name);

		if ((user->utf8string_len == len) &&
	    	    (!memcmp(user->utf8string_val, ent->name, len)))
			return ent->id;

		ent++;
	}

	return -ENOENT;
}

static int srv_lookup_group(const utf8string *user)
{
	return srv_lookup_user(user);
}

#if 0
static const char *srv_lookup_id(int id)
{
	const struct idmap_ent *ent = &idmap[0];

	while (ent->name) {
		if (id == ent->id)
			return ent->name;

		ent++;
	}

	return NULL;
}
#endif

struct nfs_inode *inode_get(nfsino_t inum)
{
	g_assert(srv.inode_table != NULL);

	return g_hash_table_lookup(srv.inode_table, GUINT_TO_POINTER(inum));
}

void inode_touch(struct nfs_inode *ino)
{
	ino->version++;
	ino->mtime = current_time.tv_sec;
}

static void inode_free(struct nfs_inode *ino)
{
	g_array_free(ino->parents, true);

	switch (ino->type) {
	case NF4DIR:
		if (ino->u.dir)
			g_hash_table_destroy(ino->u.dir);
		break;
	case NF4LNK:
		free(ino->u.linktext);
		break;
	default:
		/* do nothing */
		break;
	}

	if (ino->data) {
		free(ino->data);
		srv.space_used -= ino->size;
	}

	free(ino);
}

static struct nfs_inode *inode_new(struct nfs_cxn *cxn)
{
	struct nfs_inode *ino = calloc(1, sizeof(struct nfs_inode));
	if (!ino)
		goto out;

	ino->parents = g_array_new(false, false, sizeof(nfsino_t));
	if (!ino->parents)
		goto out_ino;

	ino->ino = next_ino++;

	ino->version = 1ULL;
	ino->ctime =
	ino->atime =
	ino->mtime = current_time.tv_sec;
	ino->mode = MODE4_RUSR;

	if (cxn) {
		ino->uid = cxn_getuid(cxn);
		ino->gid = cxn_getgid(cxn);
	}

	goto out;

out_ino:
	free(ino);
out:
	return ino;
}

struct nfs_inode *inode_new_file(struct nfs_cxn *cxn)
{
	struct nfs_inode *ino = inode_new(cxn);
	if (!ino)
		return NULL;

	ino->type = NF4REG;

	return ino;
}

static struct nfs_inode *inode_new_dir(struct nfs_cxn *cxn)
{
	struct nfs_inode *ino = inode_new(cxn);
	if (!ino)
		return NULL;

	ino->type = NF4DIR;

	ino->u.dir = g_hash_table_new_full(g_str_hash, g_str_equal,
					   free, dirent_free);
	if (!ino->u.dir) {
		inode_free(ino);
		return NULL;
	}

	return ino;
}

static struct nfs_inode *inode_new_dev(struct nfs_cxn *cxn,
				enum nfs_ftype4 type, const uint32_t *devdata)
{
	struct nfs_inode *ino = inode_new(cxn);
	if (!ino)
		return NULL;

	ino->type = type;
	memcpy(&ino->u.devdata[0], devdata, sizeof(uint32_t) * 2);

	return ino;
}

static struct nfs_inode *inode_new_symlink(struct nfs_cxn *cxn, char *linktext)
{
	struct nfs_inode *ino = inode_new(cxn);
	if (!ino)
		return NULL;

	ino->type = NF4LNK;
	ino->u.linktext = linktext;

	return ino;
}

static nfsstat4 inode_new_type(struct nfs_cxn *cxn, uint32_t objtype,
			       const struct nfs_buf *linkdata,
			       const uint32_t *specdata,
			       struct nfs_inode **ino_out)
{
	struct nfs_inode *new_ino;
	nfsstat4 status;

	*ino_out = NULL;

	switch(objtype) {
	case NF4DIR:
		new_ino = inode_new_dir(cxn);
		break;
	case NF4BLK:
	case NF4CHR:
		new_ino = inode_new_dev(cxn, objtype, specdata);
		break;
	case NF4LNK: {
		char *linktext = copy_utf8string(linkdata);
		if (!linktext) {
			status = NFS4ERR_RESOURCE;
			goto out;
		}
		new_ino = inode_new_symlink(cxn, linktext);
		if (!new_ino)
			free(linktext);
		break;
	}
	case NF4SOCK:
	case NF4FIFO:
		new_ino = inode_new(cxn);
		break;
	default:
		status = NFS4ERR_BADTYPE;
		goto out;
	}

	new_ino->type = objtype;

	if (!new_ino) {
		status = NFS4ERR_RESOURCE;
		goto out;
	}

	*ino_out = new_ino;
	status = NFS4_OK;

out:
	return status;
}

bool inode_table_init(void)
{
	struct nfs_inode *root;

	srv.inode_table = g_hash_table_new(g_direct_hash, g_direct_equal);

	root = inode_new_dir(NULL);
	if (!root)
		return false;
	root->ino = INO_ROOT;
	root->mode = 0755;
	root->uid = 0;
	root->gid = 0;
	root->size = 2;

	g_hash_table_insert(srv.inode_table, GUINT_TO_POINTER(INO_ROOT), root);

	return true;
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
		g_hash_table_remove(srv.inode_table, GUINT_TO_POINTER(ino->ino));
		inode_free(ino);
	}
}

enum nfsstat4 inode_apply_attrs(struct nfs_inode *ino,
				const struct nfs_fattr_set *attr,
			        uint64_t *bitmap_set_out,
			        struct nfs_stateid *sid,
			        bool in_setattr)
{
	uint64_t bitmap_set = 0;
	enum nfsstat4 status = NFS4_OK;

	if (attr->bitmap & fattr_read_only_mask) {
		status = NFS4ERR_INVAL;
		goto out;
	}
	if (attr->bitmap & ~fattr_supported_mask) {
		status = NFS4ERR_ATTRNOTSUPP;
		goto out;
	}

	if (attr->bitmap & (1ULL << FATTR4_SIZE)) {
		uint64_t new_size = attr->size;
		void *mem;
		struct nfs_state *st = NULL;

		/* only permit size attribute manip on files */
		if (ino->type != NF4REG) {
			if (ino->type == NF4DIR)
				status = NFS4ERR_ISDIR;
			else
				status = NFS4ERR_INVAL;
			goto out;
		}

		if (sid && sid->seqid && (sid->seqid != 0xffffffffU)) {
			uint32_t id = sid->id;

			status = stateid_lookup(id, ino->ino, nst_open, &st);
			if (status != NFS4_OK)
				goto out;

			if (!(st->share_ac & OPEN4_SHARE_ACCESS_WRITE)) {
				status = NFS4ERR_OPENMODE;
				goto out;
			}
		}

		if (new_size == ino->size)
			goto size_done;

		mem = realloc(ino->data, new_size);
		if (!new_size) {
			ino->data = NULL;
			goto size_done;
		}
		if (!mem) {
			status = NFS4ERR_NOSPC;
			goto out;
		}

		ino->data = mem;

		if (new_size > ino->size) {
			uint64_t zero = new_size - ino->size;
			memset(ino->data + ino->size, 0, zero);
			srv.space_used += zero;
		} else {
			srv.space_used -= (ino->size - new_size);
		}

size_done:
		ino->size = new_size;
		bitmap_set |= (1ULL << FATTR4_SIZE);
	}

	if (attr->bitmap & (1ULL << FATTR4_TIME_ACCESS_SET)) {
		if (attr->time_access_set.settime4_u.time.nseconds > 999999999){
			status = NFS4ERR_INVAL;
			goto out;
		}

		if (attr->time_access_set.set_it == SET_TO_CLIENT_TIME4)
			ino->atime =
			      attr->time_access_set.settime4_u.time.seconds;
		else
			ino->atime = current_time.tv_sec;

		bitmap_set |= (1ULL << FATTR4_TIME_ACCESS_SET);
	}
	if (attr->bitmap & (1ULL << FATTR4_TIME_MODIFY_SET)) {
		if (attr->time_modify_set.settime4_u.time.nseconds > 999999999){
			status = NFS4ERR_INVAL;
			goto out;
		}

		if (attr->time_modify_set.set_it == SET_TO_CLIENT_TIME4)
			ino->mtime =
			      attr->time_modify_set.settime4_u.time.seconds;
		else
			ino->mtime = current_time.tv_sec;

		bitmap_set |= (1ULL << FATTR4_TIME_MODIFY_SET);
	}
	if (attr->bitmap & (1ULL << FATTR4_MODE)) {
		if (attr->mode & ~MODE4_ALL) {
			status = NFS4ERR_BADXDR;
			goto out;
		}
		ino->mode = attr->mode;
		bitmap_set |= (1ULL << FATTR4_MODE);
	}
	if (attr->bitmap & (1ULL << FATTR4_OWNER)) {
		int x = srv_lookup_user(&attr->owner);
		if (x < 0) {
			if (debugging)
				syslog(LOG_INFO, "invalid OWNER attr: '%.*s'",
				       attr->owner.utf8string_len,
				       attr->owner.utf8string_val);
			status = NFS4ERR_INVAL;
			goto out;
		}

		ino->uid = x;
		bitmap_set |= (1ULL << FATTR4_OWNER);
	}
	if (attr->bitmap & (1ULL << FATTR4_OWNER_GROUP)) {
		int x = srv_lookup_group(&attr->owner_group);
		if (x < 0) {
			if (debugging)
				syslog(LOG_INFO, "invalid OWNER GROUP attr: '%.*s'",
				       attr->owner_group.utf8string_len,
				       attr->owner_group.utf8string_val);
			status = NFS4ERR_INVAL;
			goto out;
		}

		ino->gid = x;
		bitmap_set |= (1ULL << FATTR4_OWNER_GROUP);
	}

out:
	if (in_setattr && bitmap_set)
		inode_touch(ino);

	*bitmap_set_out = bitmap_set;
	return status;
}

nfsstat4 inode_add(struct nfs_inode *dir_ino, struct nfs_inode *new_ino,
		   const struct nfs_fattr_set *attr, const struct nfs_buf *name,
		   uint64_t *attrset, change_info4 *cinfo)
{
	nfsstat4 status;

	status = inode_apply_attrs(new_ino, attr, attrset, NULL, false);
	if (status != NFS4_OK) {
		inode_free(new_ino);
		goto out;
	}

	g_hash_table_insert(srv.inode_table, GUINT_TO_POINTER(new_ino->ino),
			    new_ino);

	cinfo->atomic = true;
	cinfo->before =
	cinfo->after = dir_ino->version;

	status = dir_add(dir_ino, name, new_ino->ino);
	if (status != NFS4_OK) {
		inode_unlink(new_ino, 0);
		goto out;
	}

	g_array_append_val(new_ino->parents, dir_ino->ino);
	cinfo->after = dir_ino->version;

out:
	return status;
}

static void print_create_args(uint32_t objtype, const struct nfs_buf *objname,
			      const struct nfs_buf *linkdata,
			      const uint32_t *specdata,
			      const struct nfs_fattr_set *attr)
{
	switch (objtype) {
	case NF4BLK:
	case NF4CHR:
		syslog(LOG_INFO, "op CREATE (%s, '%.*s', %u %u)",
		       name_nfs_ftype4[objtype],
		       objname->len, objname->val,
		       specdata[0],
		       specdata[1]);
		break;
	case NF4LNK:
		syslog(LOG_INFO, "op CREATE (%s, '%.*s', '%.*s')",
		       name_nfs_ftype4[objtype],
		       objname->len, objname->val,
		       linkdata->len, linkdata->val);
		break;
	default:
		syslog(LOG_INFO, "op CREATE (%s, '%.*s')",
		       name_nfs_ftype4[objtype],
		       objname->len, objname->val);
		break;
	}

	print_fattr("op CREATE attr", attr);
}

nfsstat4 nfs_op_create(struct nfs_cxn *cxn, struct curbuf *cur,
		       struct list_head *writes, struct rpc_write **wr)
{
	nfsstat4 status;
	struct nfs_inode *dir_ino, *new_ino;
	uint32_t objtype, specdata[2] = { 0, };
	struct nfs_buf objname, linkdata = { 0, NULL };
	struct nfs_fattr_set attr;
	uint64_t attrset = 0;
	change_info4 cinfo;

	objtype = CR32();				/* type */
	if (objtype == NF4BLK || objtype == NF4CHR) {
		specdata[0] = CR32();			/* devdata */
		specdata[1] = CR32();
	} else if (objtype == NF4LNK)
		CURBUF(&linkdata);			/* linkdata */
	CURBUF(&objname);				/* objname */

	status = cur_readattr(cur, &attr);		/* createattrs */
	if (status != NFS4_OK)
		goto out;

	if (debugging)
		print_create_args(objtype, &objname, &linkdata,
				  specdata, &attr);

	status = dir_curfh(cxn, &dir_ino);
	if (status != NFS4_OK)
		goto err_out;

	if (dir_ino->type != NF4DIR) {
		status = NFS4ERR_NOTDIR;
		goto err_out;
	}

	status = inode_new_type(cxn, objtype, &linkdata, specdata, &new_ino);
	if (status != NFS4_OK)
		goto err_out;

	status = inode_add(dir_ino, new_ino, &attr,
			   &objname, &attrset, &cinfo);
	if (status != NFS4_OK)
		goto err_out;

	cxn->current_fh = new_ino->ino;

	if (debugging)
		syslog(LOG_INFO, "   CREATE -> %u", cxn->current_fh);

err_out:
	fattr_free(&attr);
out:
	WR32(status);
	if (status == NFS4_OK) {
		WR32(cinfo.atomic ? 1 : 0);
		WR32(cinfo.before);
		WR32(cinfo.after);
		WRMAP(attrset);
	}
	return status;
}

nfsstat4 nfs_op_getattr(struct nfs_cxn *cxn, struct curbuf *cur,
		        struct list_head *writes, struct rpc_write **wr)
{
	nfsstat4 status = NFS4_OK;
	struct nfs_inode *ino;
	struct nfs_fattr_set attrset;
	bool printed = false;
	uint32_t *status_p;
	uint64_t bitmap_out = 0;

	memset(&attrset, 0, sizeof(attrset));

	status_p = WRSKIP(4);		/* ending status */

	if (cur->len < 4) {
		status = NFS4ERR_BADXDR;
		goto out;
	}

	attrset.bitmap = CURMAP();

	ino = inode_get(cxn->current_fh);
	if (!ino) {
		status = NFS4ERR_NOFILEHANDLE;
		goto out;
	}

	if (debugging && (status == NFS4_OK)) {
		print_fattr_bitmap("op GETATTR", attrset.bitmap);
		printed = true;
	}

	/* GETATTR not permitted to process write-only attrs */
	if (attrset.bitmap & ((1ULL << FATTR4_TIME_ACCESS_SET) |
			      (1ULL << FATTR4_TIME_MODIFY_SET))) {
		status = NFS4ERR_INVAL;
		goto out;
	}

	fattr_fill(ino, &attrset);

	status = wr_fattr(&attrset, &bitmap_out, writes, wr);

	fattr_free(&attrset);

	if (debugging) {
		print_fattr_bitmap("   GETATTR ->", bitmap_out);
		printed = true;
	}

out:
	if (debugging && !printed)
		syslog(LOG_INFO, "op GETATTR");

	*status_p = status;
	return status;
}

nfsstat4 nfs_op_setattr(struct nfs_cxn *cxn, struct curbuf *cur,
		        struct list_head *writes, struct rpc_write **wr)
{
	struct nfs_inode *ino;
	nfsstat4 status = NFS4_OK;
	uint64_t bitmap_out = 0;
	struct nfs_stateid sid;
	struct nfs_fattr_set attr;

	if (cur->len < 16) {
		status = NFS4ERR_BADXDR;
		goto out;
	}

	CURSID(&sid);

	status = cur_readattr(cur, &attr);
	if (status != NFS4_OK)
		goto out;

	if (debugging) {
		syslog(LOG_INFO, "op SETATTR (ID:%x)", sid.id);
		print_fattr_bitmap("   SETATTR", attr.supported_attrs);
	}

	ino = inode_get(cxn->current_fh);
	if (!ino) {
		status = NFS4ERR_NOFILEHANDLE;
		goto err_out;
	}

	status = inode_apply_attrs(ino, &attr, &bitmap_out, &sid, true);
	if (status != NFS4_OK)
		goto err_out;

	if (debugging)
		print_fattr_bitmap("   SETATTR result", bitmap_out);

err_out:
	fattr_free(&attr);
out:
	WR32(status);
	WRMAP(bitmap_out);
	return status;
}

unsigned int inode_access(const struct nfs_cxn *cxn,
			  const struct nfs_inode *ino, unsigned int req_access)
{
	unsigned int mode, rc;
	int uid, gid;

	uid = cxn_getuid(cxn);
	gid = cxn_getgid(cxn);
	if ((uid < 0) || (gid < 0)) {
		if (debugging)
			syslog(LOG_INFO, "invalid cxn uid/gid (%d/%d)",
				uid, gid);
		return 0;
	}

	mode = ino->mode & 0x7;
	if ((uid == ino->uid) || (uid == 0))
		mode |= (ino->mode >> 6) & 0x7;
	if ((gid == ino->gid) || (gid == 0))
		mode |= (ino->mode >> 3) & 0x7;

	rc = 0;
	if (mode & MODE4_ROTH)
		rc |= ACCESS4_READ;
	if ((mode & MODE4_XOTH) && (ino->type == NF4DIR))
		rc |= ACCESS4_LOOKUP;
	if (mode & MODE4_WOTH)
		rc |= ACCESS4_MODIFY;
	if (mode & MODE4_WOTH)
		rc |= ACCESS4_EXTEND;
	if ((mode & MODE4_XOTH) && (ino->type != NF4DIR))
		rc |= ACCESS4_EXECUTE;

	rc &= req_access;

	/* FIXME: check ACCESS4_DELETE */

	return rc;
}

nfsstat4 nfs_op_access(struct nfs_cxn *cxn, struct curbuf *cur,
		       struct list_head *writes, struct rpc_write **wr)
{
	nfsstat4 status = NFS4_OK;
	struct nfs_inode *ino;
	uint32_t arg_access;
	ACCESS4resok resok;

	if (cur->len < sizeof(ACCESS4args)) {
		status = NFS4ERR_BADXDR;
		goto out;
	}

	arg_access = CR32();

	if (debugging)
		syslog(LOG_INFO, "op ACCESS (0x%x)", arg_access);

	ino = inode_get(cxn->current_fh);
	if (!ino) {
		status = NFS4ERR_NOFILEHANDLE;
		goto out;
	}

	resok.access = inode_access(cxn, ino, arg_access);
	resok.supported =
		ACCESS4_READ |
		ACCESS4_LOOKUP |
		ACCESS4_MODIFY |
		ACCESS4_EXTEND |
		/* ACCESS4_DELETE | */	/* FIXME */
		ACCESS4_EXECUTE;

	resok.supported &= resok.access;

	if (debugging)
		syslog(LOG_INFO, "   ACCESS -> (ACC:%x SUP:%x)",
		       resok.access,
		       resok.supported);

out:
	WR32(status);
	if (status == NFS4_OK) {
		WR32(resok.supported);
		WR32(resok.access);
	}
	return status;
}

static bool inode_attr_cmp(const struct nfs_inode *ino,
			     const struct nfs_fattr_set *attr)
{
	uint64_t bitmap = attr->bitmap;

	/*
	 * per-server attributes
	 */
        if (bitmap & (1ULL << FATTR4_LEASE_TIME))
		if (attr->lease_time != srv.lease_time)
			return false;

	/*
	 * per-filesystem attributes
	 */
        if (bitmap & (1ULL << FATTR4_SUPPORTED_ATTRS))
		if (attr->supported_attrs != fattr_supported_mask)
			return false;
        if (bitmap & (1ULL << FATTR4_FH_EXPIRE_TYPE))
		if (attr->fh_expire_type != SRV_FH_EXP_TYPE)
			return false;
        if (bitmap & (1ULL << FATTR4_LINK_SUPPORT))
		if (attr->link_support != true)
			return false;
        if (bitmap & (1ULL << FATTR4_SYMLINK_SUPPORT))
		if (attr->symlink_support != true)
			return false;
        if (bitmap & (1ULL << FATTR4_UNIQUE_HANDLES))
		if (attr->unique_handles != true)
			return false;
        if (bitmap & (1ULL << FATTR4_CANSETTIME))
		if (attr->cansettime != true)
			return false;
        if (bitmap & (1ULL << FATTR4_CASE_INSENSITIVE))
		if (attr->case_insensitive != false)
			return false;
        if (bitmap & (1ULL << FATTR4_CASE_PRESERVING))
		if (attr->case_preserving != true)
			return false;
        if (bitmap & (1ULL << FATTR4_FILES_TOTAL))
		if (attr->files_total != g_hash_table_size(srv.inode_table))
			return false;
        if (bitmap & (1ULL << FATTR4_HOMOGENEOUS))
		if (attr->homogeneous != true)
			return false;
        if (bitmap & (1ULL << FATTR4_MAXFILESIZE))
		if (attr->maxfilesize != SRV_MAX_FILESIZE)
			return false;
        if (bitmap & (1ULL << FATTR4_MAXLINK))
		if (attr->maxlink != SRV_MAX_LINK)
			return false;
        if (bitmap & (1ULL << FATTR4_MAXNAME))
		if (attr->maxname != SRV_MAX_NAME)
			return false;
        if (bitmap & (1ULL << FATTR4_MAXREAD))
		if (attr->maxread != SRV_MAX_READ)
			return false;
        if (bitmap & (1ULL << FATTR4_MAXWRITE))
		if (attr->maxwrite != SRV_MAX_WRITE)
			return false;
        if (bitmap & (1ULL << FATTR4_NO_TRUNC))
		if (attr->no_trunc != true)
			return false;
        if (bitmap & (1ULL << FATTR4_TIME_DELTA))
		if ((attr->time_delta.seconds != 1) ||
		    (attr->time_delta.nseconds != 0))
			return false;

	/*
	 * per-object attributes
	 */
        if (bitmap & (1ULL << FATTR4_TYPE))
		if (attr->type != ino->type)
			return false;
        if (bitmap & (1ULL << FATTR4_CHANGE))
		if (attr->change != ino->version)
			return false;
        if (bitmap & (1ULL << FATTR4_SIZE))
		if (attr->size != ino->size)
			return false;
        if (bitmap & (1ULL << FATTR4_NAMED_ATTR))
		if (attr->named_attr != false)
			return false;
        if (bitmap & (1ULL << FATTR4_FSID))
		if ((attr->fsid.major != 1) || (attr->fsid.minor != 0))
			return false;
        if (bitmap & (1ULL << FATTR4_FILEHANDLE))
		if (attr->filehandle != ino->ino)
			return false;
        if (bitmap & (1ULL << FATTR4_FILEID))
		if (attr->fileid != ino->ino)
			return false;
        if (bitmap & (1ULL << FATTR4_NUMLINKS))
		if (attr->numlinks != ino->parents->len)
			return false;
        if (bitmap & (1ULL << FATTR4_RAWDEV))
		if ((attr->rawdev.specdata1 != ino->u.devdata[0]) ||
		    (attr->rawdev.specdata2 != ino->u.devdata[1]))
			return false;
        if (bitmap & (1ULL << FATTR4_TIME_ACCESS))
		if ((attr->time_access.seconds != ino->atime) ||
		    (attr->time_access.nseconds != 0))
			return false;
        if (bitmap & (1ULL << FATTR4_TIME_CREATE))
		if ((attr->time_create.seconds != ino->ctime) ||
		    (attr->time_create.nseconds != 0))
			return false;
        if (bitmap & (1ULL << FATTR4_TIME_MODIFY))
		if ((attr->time_modify.seconds != ino->mtime) ||
		    (attr->time_modify.nseconds != 0))
			return false;
        if (bitmap & (1ULL << FATTR4_MOUNTED_ON_FILEID))
		if (attr->mounted_on_fileid != ino->ino)
			return false;

	return true;
}

nfsstat4 nfs_op_verify(struct nfs_cxn *cxn, struct curbuf *cur,
		       struct list_head *writes, struct rpc_write **wr,
		       bool nverify)
{
	nfsstat4 status = NFS4_OK;
	struct nfs_inode *ino;
	struct nfs_fattr_set fattr;
	bool match;

	status = cur_readattr(cur, &fattr);
	if (status != NFS4_OK)
		goto out;

	if ((fattr.bitmap & (1ULL << FATTR4_RDATTR_ERROR)) ||
	    (fattr.bitmap & fattr_write_only_mask)) {
		status = NFS4ERR_INVAL;
		goto out_free;
	}

	if (fattr.bitmap & (!(fattr_supported_mask))) {
		status = NFS4ERR_ATTRNOTSUPP;
		goto out_free;
	}

	ino = inode_get(cxn->current_fh);
	if (!ino) {
		status = NFS4ERR_NOFILEHANDLE;
		goto out_free;
	}

	match = inode_attr_cmp(ino, &fattr);

	if (nverify) {
		if (match)
			status = NFS4ERR_SAME;
	} else {
		if (!match)
			status = NFS4ERR_NOT_SAME;
	}


out_free:
	fattr_free(&fattr);
out:
	WR32(status);
	return status;
}

