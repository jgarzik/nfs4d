#include <rpc/xdr.h>
#include <glib.h>
#include <syslog.h>
#include "nfs4_prot.h"
#include "server.h"

enum {
	FATTR_LAST		= FATTR4_MOUNTED_ON_FILEID,
};

static void encode_acl(fattr4_acl *acl,
		       struct list_head *writes, struct rpc_write **wr)
{
	struct nfs_buf nb;
	nfsace4 *ace;
	int i;

	WR32(acl->fattr4_acl_len);

	for (i = 0; i < acl->fattr4_acl_len; i++) {
		ace = &acl->fattr4_acl_val[i];
		WR32(ace->type);
		WR32(ace->flag);
		WR32(ace->access_mask);

		nb.len = ace->who.utf8string_len;
		nb.val = ace->who.utf8string_val;
		WRBUF(&nb);
	}
}

nfsstat4 wr_fattr(struct nfs_fattr_set *attr, uint64_t *_bitmap_out,
		  struct list_head *writes, struct rpc_write **wr)
{
	uint64_t bitmap = attr->bitmap;
	uint64_t bitmap_out = 0;
	struct nfs_buf nb;
	char *end, *start = WRSKIP(0);
	uint32_t *bmap[2], *attr_len;

	WR32(2);		/* bitmap array size */
	bmap[0] = WRSKIP(4);	/* bitmap array[0] */
	bmap[1] = WRSKIP(4);	/* bitmap array[1] */
	attr_len = WRSKIP(4);	/* attribute buffer length */

	if (bitmap & (1ULL << FATTR4_SUPPORTED_ATTRS)) {
		WR32(2);
		WR32(fattr_supported_mask);
		WR32(fattr_supported_mask >> 32);
		bitmap_out |= (1ULL << FATTR4_SUPPORTED_ATTRS);
	}
	if (bitmap & (1ULL << FATTR4_TYPE)) {
		WR32(attr->type);
		bitmap_out |= (1ULL << FATTR4_TYPE);
	}
	if (bitmap & (1ULL << FATTR4_FH_EXPIRE_TYPE)) {
		WR32(attr->fh_expire_type);
		bitmap_out |= (1ULL << FATTR4_FH_EXPIRE_TYPE);
	}
	if (bitmap & (1ULL << FATTR4_CHANGE)) {
		WR64(attr->change);
		bitmap_out |= (1ULL << FATTR4_CHANGE);
	}
	if (bitmap & (1ULL << FATTR4_SIZE)) {
		WR64(attr->size);
		bitmap_out |= (1ULL << FATTR4_SIZE);
	}
	if (bitmap & (1ULL << FATTR4_LINK_SUPPORT)) {
		WR32(attr->link_support ? 1 : 0);
		bitmap_out |= (1ULL << FATTR4_LINK_SUPPORT);
	}
	if (bitmap & (1ULL << FATTR4_SYMLINK_SUPPORT)) {
		WR32(attr->symlink_support ? 1 : 0);
		bitmap_out |= (1ULL << FATTR4_SYMLINK_SUPPORT);
	}
	if (bitmap & (1ULL << FATTR4_NAMED_ATTR)) {
		WR32(attr->named_attr ? 1 : 0);
		bitmap_out |= (1ULL << FATTR4_NAMED_ATTR);
	}
	if (bitmap & (1ULL << FATTR4_FSID)) {
		WR64(attr->fsid.major);
		WR64(attr->fsid.minor);
		bitmap_out |= (1ULL << FATTR4_FSID);
	}
	if (bitmap & (1ULL << FATTR4_UNIQUE_HANDLES)) {
		WR32(attr->unique_handles ? 1 : 0);
		bitmap_out |= (1ULL << FATTR4_UNIQUE_HANDLES);
	}
	if (bitmap & (1ULL << FATTR4_LEASE_TIME)) {
		WR32(attr->lease_time);
		bitmap_out |= (1ULL << FATTR4_LEASE_TIME);
	}
	if (bitmap & (1ULL << FATTR4_RDATTR_ERROR)) {
		WR32(attr->rdattr_error);
		bitmap_out |= (1ULL << FATTR4_RDATTR_ERROR);
	}
	if (bitmap & (1ULL << FATTR4_ACL)) {
		encode_acl(&attr->acl, writes, wr);
		bitmap_out |= (1ULL << FATTR4_ACL);
	}
	if (bitmap & (1ULL << FATTR4_ACLSUPPORT)) {
		WR32(attr->aclsupport);
		bitmap_out |= (1ULL << FATTR4_ACLSUPPORT);
	}
	if (bitmap & (1ULL << FATTR4_ARCHIVE)) {
		WR32(attr->archive ? 1 : 0);
		bitmap_out |= (1ULL << FATTR4_ARCHIVE);
	}
	if (bitmap & (1ULL << FATTR4_CANSETTIME)) {
		WR32(attr->cansettime ? 1 : 0);
		bitmap_out |= (1ULL << FATTR4_CANSETTIME);
	}
	if (bitmap & (1ULL << FATTR4_CASE_INSENSITIVE)) {
		WR32(attr->case_insensitive ? 1 : 0);
		bitmap_out |= (1ULL << FATTR4_CASE_INSENSITIVE);
	}
	if (bitmap & (1ULL << FATTR4_CASE_PRESERVING)) {
		WR32(attr->case_preserving ? 1 : 0);
		bitmap_out |= (1ULL << FATTR4_CASE_PRESERVING);
	}
	if (bitmap & (1ULL << FATTR4_CHOWN_RESTRICTED)) {
		WR32(attr->chown_restricted ? 1 : 0);
		bitmap_out |= (1ULL << FATTR4_CHOWN_RESTRICTED);
	}
	if (bitmap & (1ULL << FATTR4_FILEHANDLE)) {
		nb.len = attr->filehandle.nfs_fh4_len;
		nb.val = attr->filehandle.nfs_fh4_val;
		WRBUF(&nb);
		bitmap_out |= (1ULL << FATTR4_FILEHANDLE);
	}
	if (bitmap & (1ULL << FATTR4_FILEID)) {
		WR64(attr->fileid);
		bitmap_out |= (1ULL << FATTR4_FILEID);
	}
	if (bitmap & (1ULL << FATTR4_FILES_AVAIL)) {
		WR64(attr->files_avail);
		bitmap_out |= (1ULL << FATTR4_FILES_AVAIL);
	}
	if (bitmap & (1ULL << FATTR4_FILES_FREE)) {
		WR64(attr->files_free);
		bitmap_out |= (1ULL << FATTR4_FILES_FREE);
	}
	if (bitmap & (1ULL << FATTR4_FILES_TOTAL)) {
		WR64(attr->files_total);
		bitmap_out |= (1ULL << FATTR4_FILES_TOTAL);
	}

#if FS_LOCATIONS_CODE_WORKING
	if (bitmap & (1ULL << FATTR4_FS_LOCATIONS)) {
		encode_pathname(&attr->fs_locations.fs_root, &buf, &p, &buflen,
				&alloc_len);
		bitmap_out |= (1ULL << FATTR4_FS_LOCATIONS);
	}
#endif

	if (bitmap & (1ULL << FATTR4_HIDDEN)) {
		WR32(attr->hidden ? 1 : 0);
		bitmap_out |= (1ULL << FATTR4_HIDDEN);
	}
	if (bitmap & (1ULL << FATTR4_HOMOGENEOUS)) {
		WR32(attr->homogeneous ? 1 : 0);
		bitmap_out |= (1ULL << FATTR4_HOMOGENEOUS);
	}
	if (bitmap & (1ULL << FATTR4_MAXFILESIZE)) {
		WR64(attr->maxfilesize);
		bitmap_out |= (1ULL << FATTR4_MAXFILESIZE);
	}
	if (bitmap & (1ULL << FATTR4_MAXLINK)) {
		WR32(attr->maxlink);
		bitmap_out |= (1ULL << FATTR4_MAXLINK);
	}
	if (bitmap & (1ULL << FATTR4_MAXNAME)) {
		WR32(attr->maxname);
		bitmap_out |= (1ULL << FATTR4_MAXNAME);
	}
	if (bitmap & (1ULL << FATTR4_MAXREAD)) {
		WR64(attr->maxread);
		bitmap_out |= (1ULL << FATTR4_MAXREAD);
	}
	if (bitmap & (1ULL << FATTR4_MAXWRITE)) {
		WR64(attr->maxwrite);
		bitmap_out |= (1ULL << FATTR4_MAXWRITE);
	}

#if 0
	if (bitmap & (1ULL << FATTR4_MIMETYPE)) {
		encode_utf8(&attr->mimetype, &buf, &p, &buflen, &alloc_len);
		bitmap_out |= (1ULL << FATTR4_MIMETYPE);
	}
#endif

	if (bitmap & (1ULL << FATTR4_MODE)) {
		WR32(attr->mode);
		bitmap_out |= (1ULL << FATTR4_MODE);
	}
	if (bitmap & (1ULL << FATTR4_NO_TRUNC)) {
		WR32(attr->no_trunc ? 1 : 0);
		bitmap_out |= (1ULL << FATTR4_NO_TRUNC);
	}
	if (bitmap & (1ULL << FATTR4_NUMLINKS)) {
		WR32(attr->numlinks);
		bitmap_out |= (1ULL << FATTR4_NUMLINKS);
	}
	if (bitmap & (1ULL << FATTR4_OWNER)) {
		nb.len = attr->owner.utf8string_len;
		nb.val = attr->owner.utf8string_val;
		WRBUF(&nb);
		bitmap_out |= (1ULL << FATTR4_OWNER);
	}
	if (bitmap & (1ULL << FATTR4_OWNER_GROUP)) {
		nb.len = attr->owner_group.utf8string_len;
		nb.val = attr->owner_group.utf8string_val;
		WRBUF(&nb);
		bitmap_out |= (1ULL << FATTR4_OWNER_GROUP);
	}
	if (bitmap & (1ULL << FATTR4_QUOTA_AVAIL_HARD)) {
		WR64(attr->quota_avail_hard);
		bitmap_out |= (1ULL << FATTR4_QUOTA_AVAIL_HARD);
	}
	if (bitmap & (1ULL << FATTR4_QUOTA_AVAIL_SOFT)) {
		WR64(attr->quota_avail_soft);
		bitmap_out |= (1ULL << FATTR4_QUOTA_AVAIL_SOFT);
	}
	if (bitmap & (1ULL << FATTR4_QUOTA_USED)) {
		WR64(attr->quota_used);
		bitmap_out |= (1ULL << FATTR4_QUOTA_USED);
	}
	if (bitmap & (1ULL << FATTR4_RAWDEV)) {
		/* FIXME: correct order of these two dwords? */
		WR32(attr->rawdev.specdata1);
		WR32(attr->rawdev.specdata2);
		bitmap_out |= (1ULL << FATTR4_RAWDEV);
	}
	if (bitmap & (1ULL << FATTR4_SPACE_AVAIL)) {
		WR64(attr->space_avail);
		bitmap_out |= (1ULL << FATTR4_SPACE_AVAIL);
	}
	if (bitmap & (1ULL << FATTR4_SPACE_FREE)) {
		WR64(attr->space_free);
		bitmap_out |= (1ULL << FATTR4_SPACE_FREE);
	}
	if (bitmap & (1ULL << FATTR4_SPACE_TOTAL)) {
		WR64(attr->space_total);
		bitmap_out |= (1ULL << FATTR4_SPACE_TOTAL);
	}
	if (bitmap & (1ULL << FATTR4_SPACE_USED)) {
		WR64(attr->space_used);
		bitmap_out |= (1ULL << FATTR4_SPACE_USED);
	}
	if (bitmap & (1ULL << FATTR4_SYSTEM)) {
		WR32(attr->system ? 1 : 0);
		bitmap_out |= (1ULL << FATTR4_SYSTEM);
	}
	if (bitmap & (1ULL << FATTR4_TIME_ACCESS)) {
		WR64(attr->time_access.seconds);
		WR32(attr->time_access.nseconds);
		bitmap_out |= (1ULL << FATTR4_TIME_ACCESS);
	}
	if (bitmap & (1ULL << FATTR4_TIME_BACKUP)) {
		WR64(attr->time_backup.seconds);
		WR32(attr->time_backup.nseconds);
		bitmap_out |= (1ULL << FATTR4_TIME_BACKUP);
	}
	if (bitmap & (1ULL << FATTR4_TIME_CREATE)) {
		WR64(attr->time_create.seconds);
		WR32(attr->time_create.nseconds);
		bitmap_out |= (1ULL << FATTR4_TIME_CREATE);
	}
	if (bitmap & (1ULL << FATTR4_TIME_DELTA)) {
		WR64(attr->time_delta.seconds);
		WR32(attr->time_delta.nseconds);
		bitmap_out |= (1ULL << FATTR4_TIME_DELTA);
	}
	if (bitmap & (1ULL << FATTR4_TIME_METADATA)) {
		WR64(attr->time_metadata.seconds);
		WR32(attr->time_metadata.nseconds);
		bitmap_out |= (1ULL << FATTR4_TIME_METADATA);
	}
	if (bitmap & (1ULL << FATTR4_TIME_MODIFY)) {
		WR64(attr->time_modify.seconds);
		WR32(attr->time_modify.nseconds);
		bitmap_out |= (1ULL << FATTR4_TIME_MODIFY);
	}
	if (bitmap & (1ULL << FATTR4_MOUNTED_ON_FILEID)) {
		WR64(attr->mounted_on_fileid);
		bitmap_out |= (1ULL << FATTR4_MOUNTED_ON_FILEID);
	}

	*_bitmap_out = bitmap_out;

	end = WRSKIP(0);

	*bmap[0] = htonl(bitmap_out);
	*bmap[1] = htonl(bitmap_out >> 32);
	*attr_len = htonl(end - start);

	return NFS4_OK;
}

#define FATTR_DEFINE(a,b,c)				\
	if (bitmap & ( 1ULL << FATTR4_##a )) {		\
		if (!xdr_fattr4_##b(&xdr, &attr->b)) {	\
			rc = false;			\
			goto out;			\
		}					\
	}

bool fattr_decode(fattr4 *raw, struct nfs_fattr_set *attr)
{
	uint64_t bitmap;
	XDR xdr;
	bool rc = true;

	memset(attr, 0, sizeof(*attr));
	bitmap = attr->bitmap = get_bitmap(&raw->attrmask);

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

void fattr4_free(fattr4 *attr)
{
	if (!attr)
		return;

	if (attr->attrmask.bitmap4_val) {
		free(attr->attrmask.bitmap4_val);
		attr->attrmask.bitmap4_val = NULL;
		attr->attrmask.bitmap4_len = 0;
	}

	if (attr->attr_vals.attrlist4_val) {
		free(attr->attr_vals.attrlist4_val);
		attr->attr_vals.attrlist4_val = NULL;
		attr->attr_vals.attrlist4_len = 0;
	}
}

static void fattr_fill_server(struct nfs_fattr_set *attr)
{
	uint64_t bitmap = attr->bitmap;

	if (bitmap & (1ULL << FATTR4_LEASE_TIME))
		attr->lease_time = srv.lease_time;
}

static void fattr_fill_fs(struct nfs_fattr_set *attr)
{
	uint64_t bitmap = attr->bitmap;

	if (bitmap & (1ULL << FATTR4_SUPPORTED_ATTRS))
		if (set_bitmap(fattr_supported_mask, &attr->supported_attrs))
			return;		/* failure, OOM most likely */

	attr->fh_expire_type = SRV_FH_EXP_TYPE;
	attr->link_support = true;
	attr->symlink_support = true;
	attr->unique_handles = true;
	attr->cansettime = true;
	attr->case_insensitive = false;
	attr->case_preserving = true;
	attr->files_total = g_hash_table_size(srv.inode_table);
	attr->homogeneous = true;
	attr->maxfilesize = SRV_MAX_FILESIZE;
	attr->maxlink = SRV_MAX_LINK;
	attr->maxname = SRV_MAX_NAME;
	attr->maxread = SRV_MAX_READ;
	attr->maxwrite = SRV_MAX_WRITE;
	attr->no_trunc = true;
	attr->time_delta.seconds = 1;
	attr->time_delta.nseconds = 0;

	attr->files_avail =
	attr->files_free = 330000000ULL;
	attr->files_total = attr->files_free + next_ino;

	attr->space_avail =
	attr->space_free = 400000000ULL;
	attr->space_used = srv.space_used;
	attr->space_total = attr->space_used + attr->space_free;
}

static void fattr_fill_obj(struct nfs_inode *ino, struct nfs_fattr_set *attr)
{
	uint64_t bitmap = attr->bitmap;

	attr->type = ino->type;
	attr->change = ino->version;
	attr->size = ino->size;
	attr->named_attr = false;
	attr->fsid.major = 1;
	attr->fsid.minor = 0;
	attr->rdattr_error = NFS4_OK;

	if (bitmap & (1ULL << FATTR4_FILEHANDLE))
		nfs_fh_set(&attr->filehandle, ino->ino);

	attr->fileid = ino->ino;
	attr->mode = ino->mode;
	if (ino->parents && ino->parents->len)
		attr->numlinks = ino->parents->len;
	else
		attr->numlinks = 1;

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

void fattr_fill(struct nfs_inode *ino, struct nfs_fattr_set *attr)
{
	fattr_fill_server(attr);
	fattr_fill_fs(attr);
	fattr_fill_obj(ino, attr);
}

#define FATTR_DEFINE(a,b,c)				\
	if (bitmap & ( 1ULL << FATTR4_##a )) {		\
		strcat(buf, #a);			\
		strcat(buf, " ");			\
	}

void print_fattr_bitmap(const char *pfx, uint64_t bitmap)
{
	char buf[4096];

	if (!bitmap)
		return;

	sprintf(buf, "%s: ", pfx);

#include "fattr.h"

	syslog(LOG_INFO, buf);
}

#undef FATTR_DEFINE

void print_fattr(const char *pfx, fattr4 *attr)
{
	struct nfs_fattr_set as;

	if (!fattr_decode(attr, &as)) {
		syslog(LOG_WARNING, "%s: attribute decode failed", pfx);
		return;
	}

	print_fattr_bitmap(pfx, as.bitmap);
}


