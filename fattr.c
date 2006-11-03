#include <rpc/xdr.h>
#include <glib.h>
#include "nfs4_prot.h"
#include "server.h"

enum {
	FATTR_LAST		= FATTR4_MOUNTED_ON_FILEID,
};

const uint64_t fattr_write_only_mask =
	1ULL << FATTR4_TIME_ACCESS_SET |
	1ULL << FATTR4_TIME_MODIFY_SET;
const uint64_t fattr_read_write_mask =
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
const uint64_t fattr_read_only_mask =
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
const uint64_t fattr_supported_mask =
	1ULL << FATTR4_SUPPORTED_ATTRS |
	1ULL << FATTR4_TYPE |
	1ULL << FATTR4_FH_EXPIRE_TYPE |
	1ULL << FATTR4_CHANGE |
	1ULL << FATTR4_SIZE |
	1ULL << FATTR4_LINK_SUPPORT |
	1ULL << FATTR4_SYMLINK_SUPPORT |
	1ULL << FATTR4_NAMED_ATTR |
	1ULL << FATTR4_FSID |
	1ULL << FATTR4_UNIQUE_HANDLES |
	1ULL << FATTR4_LEASE_TIME |
	1ULL << FATTR4_RDATTR_ERROR |
	1ULL << FATTR4_FILEHANDLE |
	1ULL << FATTR4_CANSETTIME |
	1ULL << FATTR4_CASE_INSENSITIVE |
	1ULL << FATTR4_CASE_PRESERVING |
	1ULL << FATTR4_FILEID |
	1ULL << FATTR4_FILES_TOTAL |
	1ULL << FATTR4_HOMOGENEOUS |
	1ULL << FATTR4_MAXFILESIZE |
	1ULL << FATTR4_MAXLINK |
	1ULL << FATTR4_MAXNAME |
	1ULL << FATTR4_MAXREAD |
	1ULL << FATTR4_MAXWRITE |
	1ULL << FATTR4_NO_TRUNC |
	1ULL << FATTR4_NUMLINKS |
	1ULL << FATTR4_RAWDEV |
	1ULL << FATTR4_TIME_ACCESS |
	1ULL << FATTR4_TIME_CREATE |
	1ULL << FATTR4_TIME_DELTA |
	1ULL << FATTR4_TIME_MODIFY |
	1ULL << FATTR4_MOUNTED_ON_FILEID;

static size_t raw_pathname_size(pathname4 *path)
{
	size_t s;
	unsigned int i;

	s = path->pathname4_len * sizeof(component4);

	for (i = 0; i < path->pathname4_len; i++)
		s += path->pathname4_val[i].utf8string_len;

	return s;
}

static size_t raw_fattr_size(guint64 bitmap, struct nfs_fattr_set *attr)
{
	size_t s = sizeof(struct nfs_fattr_set);
	unsigned int i;

	if (bitmap & (1ULL << FATTR4_SUPPORTED_ATTRS))
		s += attr->supported_attrs.bitmap4_len * sizeof(uint32_t);
	if (bitmap & (1ULL << FATTR4_ACL))
		for (i = 0; i < attr->acl.fattr4_acl_len; i++) {
			s += sizeof(nfsace4);
			s += attr->acl.fattr4_acl_val[i].who.utf8string_len;
		}
	if (bitmap & (1ULL << FATTR4_FILEHANDLE))
		s += attr->filehandle.nfs_fh4_len;
	if (bitmap & (1ULL << FATTR4_FS_LOCATIONS)) {
		s += raw_pathname_size(&attr->fs_locations.fs_root);
		s += attr->fs_locations.locations.locations_len *
			sizeof(fs_location4);
		for (i = 0; i < attr->fs_locations.locations.locations_len;
		     i++) {
			fs_location4 *loc =
				&attr->fs_locations.locations.locations_val[i];
			s += loc->server.server_len;
			s += raw_pathname_size(&loc->rootpath);
		}
	}
	if (bitmap & (1ULL << FATTR4_MIMETYPE))
		s += attr->mimetype.utf8string_len;
	if (bitmap & (1ULL << FATTR4_OWNER))
		s += attr->owner.utf8string_len;
	if (bitmap & (1ULL << FATTR4_OWNER_GROUP))
		s += attr->owner_group.utf8string_len;

	return s;
}

#define FATTR_DEFINE(a,b,c)				\
	if (bitmap & ( 1ULL << FATTR4_##a ))		\
		if (!xdr_fattr4_##b(&xdr, &attr->b))	\
			goto out;

bool_t fattr_encode(fattr4 *raw, struct nfs_fattr_set *attr)
{
	XDR xdr;
	void *buf;
	guint64 bitmap = attr->bitmap;
	size_t buflen = raw_fattr_size(bitmap, attr);

	buf = g_malloc0(buflen);
	if (!buf)
		return FALSE;
	
	xdrmem_create(&xdr, buf, buflen, XDR_ENCODE);

#include "fattr.h"

	raw->attrmask.bitmap4_len = 2;
	raw->attrmask.bitmap4_val = g_new(uint32_t, 2);
	if (!raw->attrmask.bitmap4_val)
		goto out;

	raw->attrmask.bitmap4_val[0] = bitmap;
	raw->attrmask.bitmap4_val[1] = (bitmap >> 32);

	raw->attr_vals.attrlist4_len = xdr_getpos(&xdr);
	raw->attr_vals.attrlist4_val = buf;

	xdr_destroy(&xdr);
	return TRUE;

out:
	g_free(buf);
	xdr_destroy(&xdr);
	return FALSE;
}

#undef FATTR_DEFINE

#define FATTR_DEFINE(a,b,c)				\
	if (bitmap & ( 1ULL << FATTR4_##a )) {		\
		if (!xdr_fattr4_##b(&xdr, &attr->b)) {	\
			rc = FALSE;			\
			goto out;			\
		}					\
	}

bool_t fattr_decode(fattr4 *raw, struct nfs_fattr_set *attr)
{
	uint64_t bitmap = 0;
	XDR xdr;
	bool_t rc = TRUE;

	memset(attr, 0, sizeof(*attr));
	if (raw->attrmask.bitmap4_len > 0)
		bitmap = raw->attrmask.bitmap4_val[0];
	if (raw->attrmask.bitmap4_len > 1)
		bitmap |= ((uint64_t)raw->attrmask.bitmap4_val[1]) << 32;
	attr->bitmap = bitmap;

	memset(&xdr, 0, sizeof(xdr));
	xdrmem_create(&xdr, raw->attr_vals.attrlist4_val,
		      raw->attr_vals.attrlist4_len, XDR_DECODE);

#include "fattr.h"

out:
	xdr_destroy(&xdr);
	return rc;
}

#undef FATTR_DEFINE

void fattr_free(struct nfs_fattr_set *attr)
{
	/* FIXME */
}

void fattr_fill_server(struct nfs_fattr_set *attr)
{
	guint64 bitmap = attr->bitmap;

	if (bitmap & (1ULL << FATTR4_LEASE_TIME))
		attr->lease_time = 5 * 60;
}

void fattr_fill_fs(struct nfs_fattr_set *attr)
{
	guint64 bitmap = attr->bitmap;

	if (bitmap & (1ULL << FATTR4_SUPPORTED_ATTRS)) {
		bitmap4 *map = &attr->supported_attrs;
		map->bitmap4_len = 2;
		map->bitmap4_val = g_new(uint32_t, 2);
		if (!map->bitmap4_val)
			return;

		map->bitmap4_val[0] = (uint32_t) fattr_supported_mask;
		map->bitmap4_val[1] = (fattr_supported_mask >> 32);
	}

	attr->fh_expire_type = FH4_PERSISTENT;
	attr->link_support = TRUE;
	attr->symlink_support = TRUE;
	attr->unique_handles = TRUE;
	attr->cansettime = TRUE;
	attr->case_insensitive = FALSE;
	attr->case_preserving = TRUE;
	attr->files_total = g_hash_table_size(srv.inode_table);
	attr->homogeneous = TRUE;
	attr->maxfilesize = 0xffffffffULL;
	attr->maxlink = SRV_MAX_LINK;
	attr->maxname = SRV_MAX_NAME;
	attr->maxread = SRV_MAX_READ;
	attr->maxwrite = SRV_MAX_WRITE;
	attr->no_trunc = TRUE;
	attr->time_delta.seconds = 1;
	attr->time_delta.nseconds = 0;
}

void fattr_fill_obj(struct nfs_inode *ino, struct nfs_fattr_set *attr)
{
	guint64 bitmap = attr->bitmap;

	attr->type = ino->type;
	attr->change = ino->version;
	attr->size = ino->size;
	attr->named_attr = FALSE;
	attr->fsid.major = 1;
	attr->fsid.minor = 0;
	attr->rdattr_error = NFS4_OK;

	if (bitmap & (1ULL << FATTR4_FILEHANDLE))
		nfs_fh_set(&attr->filehandle, ino->ino);

	attr->fileid = ino->ino;
	attr->mode = ino->mode;
	attr->numlinks = ino->parents->len;

	if (ino->type == NF4BLK || ino->type == NF4CHR)
		memcpy(&attr->rawdev, &ino->u.devdata, sizeof(specdata4));
	else
		memset(&attr->rawdev, 0, sizeof(specdata4));

	attr->time_access.seconds = ino->atime;
	attr->time_access.nseconds = 0;
	attr->time_create.seconds = ino->ctime;
	attr->time_create.nseconds = 0;
	attr->time_modify.seconds = ino->mtime;
	attr->time_modify.nseconds = 0;

	attr->mounted_on_fileid = ino->ino;
}

