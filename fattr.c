#include <rpc/xdr.h>
#include <glib.h>
#include <syslog.h>
#include "nfs4_prot.h"
#include "server.h"

#define XDR_QUADLEN(l)		(((l) + 3) >> 2)

enum {
	FATTR_LAST		= FATTR4_MOUNTED_ON_FILEID,
};

#define GROW_ATTR_BUF(sz)				\
	do {						\
		if (buflen < (sz)) {			\
			alloc_len += ((sz) + 512);	\
			buflen += ((sz) + 512);		\
			buf = realloc(buf, alloc_len);	\
		}					\
	} while (0)

#define WRITE32(val)					\
	do {						\
		GROW_ATTR_BUF(4);			\
		*p++ = GUINT32_TO_BE(val);		\
		buflen -= 4;				\
	} while (0)

#define WRITE64(val)					\
	do {						\
		GROW_ATTR_BUF(8);			\
		*p++ = GUINT32_TO_BE(val);		\
		*p++ = GUINT32_TO_BE((val) >> 32);	\
		buflen -= 8;				\
	} while (0)

#define WRITEMEM(membuf, memlen)			\
	do {						\
		unsigned int ql = XDR_QUADLEN(memlen);	\
		GROW_ATTR_BUF((ql + 1) * 4);		\
		*(p + ql - 1) = 0;			\
		memcpy(p, membuf, memlen);		\
		p += ql;				\
		buflen -= (ql * 4);			\
	} while (0)

static void encode_utf8(utf8string *s, uint32_t **base_out,
			uint32_t **buf_out, size_t *buflen_out,
			size_t *alloc_len_out)
{
	uint32_t *buf = *base_out;
	uint32_t *p = *buf_out;
	size_t buflen = *buflen_out;
	size_t alloc_len = *alloc_len_out;

	WRITE32(s->utf8string_len);
	if (s->utf8string_len)
		WRITEMEM(s->utf8string_val, s->utf8string_len);

	*base_out = buf;
	*buf_out = p;
	*buflen_out = buflen;
	*alloc_len_out = alloc_len;
}

#if FS_LOCATIONS_CODE_WORKING
static void encode_pathname(pathname4 *pathname, uint32_t **base_out,
			    uint32_t **buf_out, size_t *buflen_out,
			    size_t *alloc_len_out)
{
	uint32_t *buf = *base_out;
	uint32_t *p = *buf_out;
	size_t buflen = *buflen_out;
	size_t alloc_len = *alloc_len_out;
	int i;

	WRITE32(pathname->pathname4_len);

	for (i = 0; i < pathname->pathname4_len; i++)
		encode_utf8(&pathname->pathname4_val[i], &buf, &p,
				 &buflen, &alloc_len);

	*base_out = buf;
	*buf_out = p;
	*buflen_out = buflen;
	*alloc_len_out = alloc_len;
}
#endif

static void encode_acl(fattr4_acl *acl, uint32_t **base_out,
		       uint32_t **buf_out, size_t *buflen_out,
		       size_t *alloc_len_out)
{
	uint32_t *buf = *base_out;
	uint32_t *p = *buf_out;
	size_t buflen = *buflen_out;
	size_t alloc_len = *alloc_len_out;
	nfsace4 *ace;
	int i;

	WRITE32(acl->fattr4_acl_len);

	for (i = 0; i < acl->fattr4_acl_len; i++) {
		ace = &acl->fattr4_acl_val[i];
		WRITE32(ace->type);
		WRITE32(ace->flag);
		WRITE32(ace->access_mask);
		encode_utf8(&ace->who, &buf, &p, &buflen, &alloc_len);
	}

	*base_out = buf;
	*buf_out = p;
	*buflen_out = buflen;
	*alloc_len_out = alloc_len;
}

bool_t fattr_encode(fattr4 *raw, struct nfs_fattr_set *attr)
{
	uint32_t *buf;
	guint64 bitmap = attr->bitmap;
	guint64 bitmap_out = 0;
	size_t buflen, alloc_len = 1024;
	uint32_t *p;
	void *p1, *p2;

	buf = malloc(alloc_len);
	if (!buf)
		return FALSE;
	buflen = alloc_len;

	memset(buf, 0xffffffff, alloc_len);

	p = buf;

	if (bitmap & (1ULL << FATTR4_SUPPORTED_ATTRS)) {
		WRITE32(2);
		WRITE64(fattr_supported_mask);
		bitmap_out |= (1ULL << FATTR4_SUPPORTED_ATTRS);
	}
	if (bitmap & (1ULL << FATTR4_TYPE)) {
		WRITE32(attr->type);
		bitmap_out |= (1ULL << FATTR4_TYPE);
	}
	if (bitmap & (1ULL << FATTR4_FH_EXPIRE_TYPE)) {
		WRITE32(attr->fh_expire_type);
		bitmap_out |= (1ULL << FATTR4_FH_EXPIRE_TYPE);
	}
	if (bitmap & (1ULL << FATTR4_CHANGE)) {
		WRITE64(attr->change);
		bitmap_out |= (1ULL << FATTR4_CHANGE);
	}
	if (bitmap & (1ULL << FATTR4_SIZE)) {
		WRITE64(attr->size);
		bitmap_out |= (1ULL << FATTR4_SIZE);
	}
	if (bitmap & (1ULL << FATTR4_LINK_SUPPORT)) {
		WRITE32(attr->link_support ? 1 : 0);
		bitmap_out |= (1ULL << FATTR4_LINK_SUPPORT);
	}
	if (bitmap & (1ULL << FATTR4_SYMLINK_SUPPORT)) {
		WRITE32(attr->symlink_support ? 1 : 0);
		bitmap_out |= (1ULL << FATTR4_SYMLINK_SUPPORT);
	}
	if (bitmap & (1ULL << FATTR4_NAMED_ATTR)) {
		WRITE32(attr->named_attr ? 1 : 0);
		bitmap_out |= (1ULL << FATTR4_NAMED_ATTR);
	}
	if (bitmap & (1ULL << FATTR4_FSID)) {
		WRITE64(attr->fsid.major);
		WRITE64(attr->fsid.minor);
		bitmap_out |= (1ULL << FATTR4_FSID);
	}
	if (bitmap & (1ULL << FATTR4_UNIQUE_HANDLES)) {
		WRITE32(attr->unique_handles ? 1 : 0);
		bitmap_out |= (1ULL << FATTR4_UNIQUE_HANDLES);
	}
	if (bitmap & (1ULL << FATTR4_LEASE_TIME)) {
		WRITE32(attr->lease_time);
		bitmap_out |= (1ULL << FATTR4_LEASE_TIME);
	}
	if (bitmap & (1ULL << FATTR4_RDATTR_ERROR)) {
		WRITE32(attr->rdattr_error);
		bitmap_out |= (1ULL << FATTR4_RDATTR_ERROR);
	}
	if (bitmap & (1ULL << FATTR4_ACL)) {
		encode_acl(&attr->acl, &buf, &p, &buflen, &alloc_len);
		bitmap_out |= (1ULL << FATTR4_ACL);
	}
	if (bitmap & (1ULL << FATTR4_ACLSUPPORT)) {
		WRITE32(attr->aclsupport);
		bitmap_out |= (1ULL << FATTR4_ACLSUPPORT);
	}
	if (bitmap & (1ULL << FATTR4_ARCHIVE)) {
		WRITE32(attr->archive ? 1 : 0);
		bitmap_out |= (1ULL << FATTR4_ARCHIVE);
	}
	if (bitmap & (1ULL << FATTR4_CANSETTIME)) {
		WRITE32(attr->cansettime ? 1 : 0);
		bitmap_out |= (1ULL << FATTR4_CANSETTIME);
	}
	if (bitmap & (1ULL << FATTR4_CASE_INSENSITIVE)) {
		WRITE32(attr->case_insensitive ? 1 : 0);
		bitmap_out |= (1ULL << FATTR4_CASE_INSENSITIVE);
	}
	if (bitmap & (1ULL << FATTR4_CASE_PRESERVING)) {
		WRITE32(attr->case_preserving ? 1 : 0);
		bitmap_out |= (1ULL << FATTR4_CASE_PRESERVING);
	}
	if (bitmap & (1ULL << FATTR4_CHOWN_RESTRICTED)) {
		WRITE32(attr->chown_restricted ? 1 : 0);
		bitmap_out |= (1ULL << FATTR4_CHOWN_RESTRICTED);
	}
	if (bitmap & (1ULL << FATTR4_FILEHANDLE)) {
		WRITE32(attr->filehandle.nfs_fh4_len);
		WRITEMEM(attr->filehandle.nfs_fh4_val,
			 attr->filehandle.nfs_fh4_len);
		bitmap_out |= (1ULL << FATTR4_FILEHANDLE);
	}
	if (bitmap & (1ULL << FATTR4_FILEID)) {
		WRITE64(attr->fileid);
		bitmap_out |= (1ULL << FATTR4_FILEID);
	}
	if (bitmap & (1ULL << FATTR4_FILES_AVAIL)) {
		WRITE64(attr->files_avail);
		bitmap_out |= (1ULL << FATTR4_FILES_AVAIL);
	}
	if (bitmap & (1ULL << FATTR4_FILES_FREE)) {
		WRITE64(attr->files_free);
		bitmap_out |= (1ULL << FATTR4_FILES_FREE);
	}
	if (bitmap & (1ULL << FATTR4_FILES_TOTAL)) {
		WRITE64(attr->files_total);
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
		WRITE32(attr->hidden ? 1 : 0);
		bitmap_out |= (1ULL << FATTR4_HIDDEN);
	}
	if (bitmap & (1ULL << FATTR4_HOMOGENEOUS)) {
		WRITE32(attr->homogeneous ? 1 : 0);
		bitmap_out |= (1ULL << FATTR4_HOMOGENEOUS);
	}
	if (bitmap & (1ULL << FATTR4_MAXFILESIZE)) {
		WRITE64(attr->maxfilesize);
		bitmap_out |= (1ULL << FATTR4_MAXFILESIZE);
	}
	if (bitmap & (1ULL << FATTR4_MAXLINK)) {
		WRITE32(attr->maxlink);
		bitmap_out |= (1ULL << FATTR4_MAXLINK);
	}
	if (bitmap & (1ULL << FATTR4_MAXNAME)) {
		WRITE32(attr->maxname);
		bitmap_out |= (1ULL << FATTR4_MAXNAME);
	}
	if (bitmap & (1ULL << FATTR4_MAXREAD)) {
		WRITE64(attr->maxread);
		bitmap_out |= (1ULL << FATTR4_MAXREAD);
	}
	if (bitmap & (1ULL << FATTR4_MAXWRITE)) {
		WRITE64(attr->maxwrite);
		bitmap_out |= (1ULL << FATTR4_MAXWRITE);
	}

#if 0
	if (bitmap & (1ULL << FATTR4_MIMETYPE)) {
		encode_utf8(&attr->mimetype, &buf, &p, &buflen, &alloc_len);
		bitmap_out |= (1ULL << FATTR4_MIMETYPE);
	}
#endif

	if (bitmap & (1ULL << FATTR4_MODE)) {
		WRITE32(attr->mode);
		bitmap_out |= (1ULL << FATTR4_MODE);
	}
	if (bitmap & (1ULL << FATTR4_NO_TRUNC)) {
		WRITE32(attr->no_trunc ? 1 : 0);
		bitmap_out |= (1ULL << FATTR4_NO_TRUNC);
	}
	if (bitmap & (1ULL << FATTR4_NUMLINKS)) {
		WRITE32(attr->numlinks);
		bitmap_out |= (1ULL << FATTR4_NUMLINKS);
	}
	if (bitmap & (1ULL << FATTR4_OWNER)) {
		encode_utf8(&attr->owner, &buf, &p, &buflen, &alloc_len);
		bitmap_out |= (1ULL << FATTR4_OWNER);
	}
	if (bitmap & (1ULL << FATTR4_OWNER_GROUP)) {
		encode_utf8(&attr->owner_group, &buf, &p, &buflen, &alloc_len);
		bitmap_out |= (1ULL << FATTR4_OWNER_GROUP);
	}
	if (bitmap & (1ULL << FATTR4_QUOTA_AVAIL_HARD)) {
		WRITE64(attr->quota_avail_hard);
		bitmap_out |= (1ULL << FATTR4_QUOTA_AVAIL_HARD);
	}
	if (bitmap & (1ULL << FATTR4_QUOTA_AVAIL_SOFT)) {
		WRITE64(attr->quota_avail_soft);
		bitmap_out |= (1ULL << FATTR4_QUOTA_AVAIL_SOFT);
	}
	if (bitmap & (1ULL << FATTR4_QUOTA_USED)) {
		WRITE64(attr->quota_used);
		bitmap_out |= (1ULL << FATTR4_QUOTA_USED);
	}
	if (bitmap & (1ULL << FATTR4_RAWDEV)) {
		/* FIXME: correct order of these two dwords? */
		WRITE32(attr->rawdev.specdata1);
		WRITE32(attr->rawdev.specdata2);
		bitmap_out |= (1ULL << FATTR4_RAWDEV);
	}
	if (bitmap & (1ULL << FATTR4_SPACE_AVAIL)) {
		WRITE64(attr->space_avail);
		bitmap_out |= (1ULL << FATTR4_SPACE_AVAIL);
	}
	if (bitmap & (1ULL << FATTR4_SPACE_FREE)) {
		WRITE64(attr->space_free);
		bitmap_out |= (1ULL << FATTR4_SPACE_FREE);
	}
	if (bitmap & (1ULL << FATTR4_SPACE_TOTAL)) {
		WRITE64(attr->space_total);
		bitmap_out |= (1ULL << FATTR4_SPACE_TOTAL);
	}
	if (bitmap & (1ULL << FATTR4_SPACE_USED)) {
		WRITE64(attr->space_used);
		bitmap_out |= (1ULL << FATTR4_SPACE_USED);
	}
	if (bitmap & (1ULL << FATTR4_SYSTEM)) {
		WRITE32(attr->system ? 1 : 0);
		bitmap_out |= (1ULL << FATTR4_SYSTEM);
	}
	if (bitmap & (1ULL << FATTR4_TIME_ACCESS)) {
		WRITE64(attr->time_access.seconds);
		WRITE32(attr->time_access.nseconds);
		bitmap_out |= (1ULL << FATTR4_TIME_ACCESS);
	}
	if (bitmap & (1ULL << FATTR4_TIME_BACKUP)) {
		WRITE64(attr->time_backup.seconds);
		WRITE32(attr->time_backup.nseconds);
		bitmap_out |= (1ULL << FATTR4_TIME_BACKUP);
	}
	if (bitmap & (1ULL << FATTR4_TIME_CREATE)) {
		WRITE64(attr->time_create.seconds);
		WRITE32(attr->time_create.nseconds);
		bitmap_out |= (1ULL << FATTR4_TIME_CREATE);
	}
	if (bitmap & (1ULL << FATTR4_TIME_DELTA)) {
		WRITE64(attr->time_delta.seconds);
		WRITE32(attr->time_delta.nseconds);
		bitmap_out |= (1ULL << FATTR4_TIME_DELTA);
	}
	if (bitmap & (1ULL << FATTR4_TIME_METADATA)) {
		WRITE64(attr->time_metadata.seconds);
		WRITE32(attr->time_metadata.nseconds);
		bitmap_out |= (1ULL << FATTR4_TIME_METADATA);
	}
	if (bitmap & (1ULL << FATTR4_TIME_MODIFY)) {
		WRITE64(attr->time_modify.seconds);
		WRITE32(attr->time_modify.nseconds);
		bitmap_out |= (1ULL << FATTR4_TIME_MODIFY);
	}
	if (bitmap & (1ULL << FATTR4_MOUNTED_ON_FILEID)) {
		WRITE64(attr->mounted_on_fileid);
		bitmap_out |= (1ULL << FATTR4_MOUNTED_ON_FILEID);
	}

	if (set_bitmap(bitmap_out, &raw->attrmask))
		goto out;

	p1 = buf;
	p2 = p;

	raw->attr_vals.attrlist4_len = p2 - p1;
	if (!raw->attr_vals.attrlist4_len)
		raw->attr_vals.attrlist4_val = NULL;
	else
		raw->attr_vals.attrlist4_val = p1;

	return TRUE;

out:
	free(buf);
	return FALSE;
}

#define FATTR_DEFINE(a,b,c)				\
	if (bitmap & ( 1ULL << FATTR4_##a )) {		\
		if (!xdr_fattr4_##b(&xdr, &attr->b)) {	\
			rc = FALSE;			\
			goto out;			\
		}					\
	}

bool_t fattr_decode(fattr4 *raw, struct nfs_fattr_set *attr)
{
	uint64_t bitmap;
	XDR xdr;
	bool_t rc = TRUE;

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
	guint64 bitmap = attr->bitmap;

	if (bitmap & (1ULL << FATTR4_LEASE_TIME))
		attr->lease_time = srv.lease_time;
}

static void fattr_fill_fs(struct nfs_fattr_set *attr)
{
	guint64 bitmap = attr->bitmap;

	if (bitmap & (1ULL << FATTR4_SUPPORTED_ATTRS))
		if (set_bitmap(fattr_supported_mask, &attr->supported_attrs))
			return;		/* failure, OOM most likely */

	attr->fh_expire_type = SRV_FH_EXP_TYPE;
	attr->link_support = TRUE;
	attr->symlink_support = TRUE;
	attr->unique_handles = TRUE;
	attr->cansettime = TRUE;
	attr->case_insensitive = FALSE;
	attr->case_preserving = TRUE;
	attr->files_total = g_hash_table_size(srv.inode_table);
	attr->homogeneous = TRUE;
	attr->maxfilesize = SRV_MAX_FILESIZE;
	attr->maxlink = SRV_MAX_LINK;
	attr->maxname = SRV_MAX_NAME;
	attr->maxread = SRV_MAX_READ;
	attr->maxwrite = SRV_MAX_WRITE;
	attr->no_trunc = TRUE;
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


