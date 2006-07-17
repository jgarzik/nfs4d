#include <stdlib.h>
#include <string.h>
#include <ctype.h>
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

	ino->version = 1ULL;
	ino->ctime =
	ino->atime =
	ino->mtime = current_time.tv_sec;
	ino->mode = MODE4_RUSR;
	ino->uid = 99999999;
	ino->gid = 99999999;

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

	inode_table = g_hash_table_new(g_direct_hash, g_direct_equal);

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

static const uint64_t write_only_mask =
	1ULL << FATTR4_TIME_ACCESS_SET |
	1ULL << FATTR4_TIME_MODIFY_SET;
static const uint64_t read_write_mask =
	1ULL << FATTR4_SIZE |
	1ULL << FATTR4_ACL |
	1ULL << FATTR4_ARCHIVE |
	1ULL << FATTR4_HIDDEN |
	1ULL << FATTR4_MIMETYPE |
	1ULL << FATTR4_MODE |
	1ULL << FATTR4_OWNER |
	1ULL << FATTR4_OWNER_GROUP |
	1ULL << FATTR4_SYSTEM |
	1ULL << FATTR4_TIME_BACKUP |
	1ULL << FATTR4_TIME_CREATE;
static const uint64_t read_only_mask =
	1ULL << FATTR4_SUPPORTED_ATTRS |
	1ULL << FATTR4_TYPE |
	1ULL << FATTR4_FH_EXPIRE_TYPE |
	1ULL << FATTR4_CHANGE |
	1ULL << FATTR4_LINK_SUPPORT |
	1ULL << FATTR4_SYMLINK_SUPPORT |
	1ULL << FATTR4_NAMED_ATTR |
	1ULL << FATTR4_FSID |
	1ULL << FATTR4_UNIQUE_HANDLES |
	1ULL << FATTR4_LEASE_TIME |
	1ULL << FATTR4_RDATTR_ERROR |
	1ULL << FATTR4_FILEHANDLE |
	1ULL << FATTR4_ACLSUPPORT |
	1ULL << FATTR4_CANSETTIME |
	1ULL << FATTR4_CASE_INSENSITIVE |
	1ULL << FATTR4_CASE_PRESERVING |
	1ULL << FATTR4_CHOWN_RESTRICTED |
	1ULL << FATTR4_FILEID |
	1ULL << FATTR4_FILES_AVAIL |
	1ULL << FATTR4_FILES_FREE |
	1ULL << FATTR4_FILES_TOTAL |
	1ULL << FATTR4_FS_LOCATIONS |
	1ULL << FATTR4_HOMOGENEOUS |
	1ULL << FATTR4_MAXFILESIZE |
	1ULL << FATTR4_MAXLINK |
	1ULL << FATTR4_MAXNAME |
	1ULL << FATTR4_MAXREAD |
	1ULL << FATTR4_MAXWRITE |
	1ULL << FATTR4_NO_TRUNC |
	1ULL << FATTR4_NUMLINKS |
	1ULL << FATTR4_QUOTA_AVAIL_HARD |
	1ULL << FATTR4_QUOTA_AVAIL_SOFT |
	1ULL << FATTR4_QUOTA_USED |
	1ULL << FATTR4_RAWDEV |
	1ULL << FATTR4_SPACE_AVAIL |
	1ULL << FATTR4_SPACE_FREE |
	1ULL << FATTR4_SPACE_TOTAL |
	1ULL << FATTR4_SPACE_USED |
	1ULL << FATTR4_TIME_ACCESS |
	1ULL << FATTR4_TIME_DELTA |
	1ULL << FATTR4_TIME_METADATA |
	1ULL << FATTR4_TIME_MODIFY |
	1ULL << FATTR4_MOUNTED_ON_FILEID;

static int int_from_utf8string(utf8string *str_in)
{
	gchar *s;
	int i, rc = -1;

	s = copy_utf8string(str_in);
	if (!s)
		return -1;

	for (i = 0; i < strlen(s); i++)
		if (!isdigit(s[i]))
			goto out;

	rc = atoi(s);

out:
	g_free(s);
	return rc;
}

static enum nfsstat4 inode_apply_attrs(struct nfs_inode *ino, fattr4 *raw_attr,
				       uint64_t *bitmap_set_out)
{
	struct nfs_fattr_set fattr;
	uint64_t bitmap_set = 0;
	static const uint64_t notsupp_mask =
		1ULL << FATTR4_ACL |
		1ULL << FATTR4_ARCHIVE |
		1ULL << FATTR4_HIDDEN |
		1ULL << FATTR4_MIMETYPE |
		1ULL << FATTR4_SYSTEM |
		1ULL << FATTR4_TIME_BACKUP |
		1ULL << FATTR4_TIME_CREATE;

	if (!fattr_parse(raw_attr, &fattr))
		return NFS4ERR_INVAL;

	if (fattr.bitmap & read_only_mask)
		return NFS4ERR_INVAL;
	if (fattr.bitmap & notsupp_mask)
		return NFS4ERR_NOTSUPP;

	if (fattr.bitmap & (1ULL << FATTR4_SIZE)) /* TODO: truncate */
		return NFS4ERR_NOTSUPP;

	if (fattr.bitmap & (1ULL << FATTR4_TIME_ACCESS_SET)) {
		if (fattr.time_access_set.set_it == SET_TO_CLIENT_TIME4)
			ino->atime =
			      fattr.time_access_set.settime4_u.time.seconds;
		else
			ino->atime = current_time.tv_sec;

		bitmap_set |= (1ULL << FATTR4_TIME_ACCESS_SET);
	}
	if (fattr.bitmap & (1ULL << FATTR4_TIME_MODIFY_SET)) {
		if (fattr.time_modify_set.set_it == SET_TO_CLIENT_TIME4)
			ino->mtime =
			      fattr.time_modify_set.settime4_u.time.seconds;
		else
			ino->mtime = current_time.tv_sec;

		bitmap_set |= (1ULL << FATTR4_TIME_MODIFY_SET);
	}
	if (fattr.bitmap & (1ULL << FATTR4_MODE)) {
		ino->mode = fattr.mode;
		bitmap_set |= (1ULL << FATTR4_MODE);
	}
	if (fattr.bitmap & (1ULL << FATTR4_OWNER)) {
		int x = int_from_utf8string(&fattr.owner);
		if (x < 0)
			return NFS4ERR_INVAL;
		
		ino->uid = x;
		bitmap_set |= (1ULL << FATTR4_OWNER);
	}
	if (fattr.bitmap & (1ULL << FATTR4_OWNER_GROUP)) {
		int x = int_from_utf8string(&fattr.owner);
		if (x < 0)
			return NFS4ERR_INVAL;
		
		ino->gid = x;
		bitmap_set |= (1ULL << FATTR4_OWNER_GROUP);
	}

	fattr_free(&fattr);

	*bitmap_set_out = bitmap_set;
	return NFS4_OK;
}

bool_t nfs_op_create(struct nfs_client *cli, CREATE4args *arg, COMPOUND4res *cres)
{
	struct nfs_resop4 resop;
	CREATE4res *res;
	CREATE4resok *resok;
	nfsstat4 status = NFS4_OK;
	struct nfs_inode *dir_ino, *new_ino;
	uint64_t bitmap_set;
	uint32_t *bitmap_alloc;

	memset(&resop, 0, sizeof(resop));
	resop.resop = OP_CREATE;
	res = &resop.nfs_resop4_u.opcreate;
	resok = &res->CREATE4res_u.resok4;

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

	status = inode_apply_attrs(new_ino, &arg->createattrs, &bitmap_set);
	if (status != NFS4_OK) {
		inode_free(new_ino);
		goto out;
	}

	bitmap_alloc = g_new0(uint32_t, 2);
	if (!bitmap_alloc) {
		inode_free(new_ino);
		status = NFS4ERR_RESOURCE;
		goto out;
	}
	bitmap_alloc[0] = bitmap_set;
	bitmap_alloc[1] = (bitmap_set >> 32);

	resok->cinfo.atomic = TRUE;
	resok->cinfo.before =
	resok->cinfo.after = dir_ino->version;

	status = dir_add(dir_ino, &arg->objname, new_ino->ino);
	if (status != NFS4_OK) {
		inode_free(new_ino);
		g_free(bitmap_alloc);
		goto out;
	}

	g_array_append_val(new_ino->parents, dir_ino->ino);
	resok->cinfo.after = dir_ino->version;
	resok->attrset.bitmap4_len = 2;
	resok->attrset.bitmap4_val = bitmap_alloc;

	cli->current_fh = new_ino->ino;

out:
	res->status = status;
	return push_resop(cres, &resop, status);
}

