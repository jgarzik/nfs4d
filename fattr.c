#include <rpc/xdr.h>
#include <glib.h>
#include <syslog.h>
#include "nfs4_prot.h"
#include "server.h"

enum {
	FATTR_LAST		= FATTR4_MOUNTED_ON_FILEID,
};

#if 0
static void encode_acl(const fattr4_acl *acl,
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
#endif

nfsstat4 cur_readacl(struct curbuf *cur, fattr4_acl *acl)
{
	/* FIXME */
	return NFS4ERR_NOTSUPP;
}

#define INC32(x)	total += 4
#define INC64(x)	total += 8
#define INCMAP(x)	total += (4 * 3)
#define INCBUF(nb)	total += 4 + (XDR_QUADLEN((nb)->len) * 4)

unsigned int fattr_size(const struct nfs_fattr_set *attr)
{
	uint64_t bitmap = attr->bitmap;
	unsigned int total = 0;

	if (bitmap & (1ULL << FATTR4_SUPPORTED_ATTRS)) {
		INCMAP(fattr_supported_mask);
	}
	if (bitmap & (1ULL << FATTR4_TYPE)) {
		INC32(attr->type);
	}
	if (bitmap & (1ULL << FATTR4_FH_EXPIRE_TYPE)) {
		INC32(attr->fh_expire_type);
	}
	if (bitmap & (1ULL << FATTR4_CHANGE)) {
		INC64(attr->change);
	}
	if (bitmap & (1ULL << FATTR4_SIZE)) {
		INC64(attr->size);
	}
	if (bitmap & (1ULL << FATTR4_LINK_SUPPORT)) {
		INC32(attr->link_support ? 1 : 0);
	}
	if (bitmap & (1ULL << FATTR4_SYMLINK_SUPPORT)) {
		INC32(attr->symlink_support ? 1 : 0);
	}
	if (bitmap & (1ULL << FATTR4_NAMED_ATTR)) {
		INC32(attr->named_attr ? 1 : 0);
	}
	if (bitmap & (1ULL << FATTR4_FSID)) {
		INC64(attr->fsid.major);
		INC64(attr->fsid.minor);
	}
	if (bitmap & (1ULL << FATTR4_UNIQUE_HANDLES)) {
		INC32(attr->unique_handles ? 1 : 0);
	}
	if (bitmap & (1ULL << FATTR4_LEASE_TIME)) {
		INC32(attr->lease_time);
	}
	if (bitmap & (1ULL << FATTR4_RDATTR_ERROR)) {
		INC32(attr->rdattr_error);
	}

#if 0 /* FIXME */
	if (bitmap & (1ULL << FATTR4_ACL)) {
		encode_acl(&attr->acl, writes, wr);
	}
#endif

	if (bitmap & (1ULL << FATTR4_ACLSUPPORT)) {
		INC32(attr->aclsupport);
	}
	if (bitmap & (1ULL << FATTR4_ARCHIVE)) {
		INC32(attr->archive ? 1 : 0);
	}
	if (bitmap & (1ULL << FATTR4_CANSETTIME)) {
		INC32(attr->cansettime ? 1 : 0);
	}
	if (bitmap & (1ULL << FATTR4_CASE_INSENSITIVE)) {
		INC32(attr->case_insensitive ? 1 : 0);
	}
	if (bitmap & (1ULL << FATTR4_CASE_PRESERVING)) {
		INC32(attr->case_preserving ? 1 : 0);
	}
	if (bitmap & (1ULL << FATTR4_CHOWN_RESTRICTED)) {
		INC32(attr->chown_restricted ? 1 : 0);
	}
	if (bitmap & (1ULL << FATTR4_FILEHANDLE)) {
		INC32(1);
		INC32(attr->filehandle);
	}
	if (bitmap & (1ULL << FATTR4_FILEID)) {
		INC64(attr->fileid);
	}
	if (bitmap & (1ULL << FATTR4_FILES_AVAIL)) {
		INC64(attr->files_avail);
	}
	if (bitmap & (1ULL << FATTR4_FILES_FREE)) {
		INC64(attr->files_free);
	}
	if (bitmap & (1ULL << FATTR4_FILES_TOTAL)) {
		INC64(attr->files_total);
	}

#if FS_LOCATIONS_CODE_WORKING
	if (bitmap & (1ULL << FATTR4_FS_LOCATIONS)) {
		encode_pathname(&attr->fs_locations.fs_root, &buf, &p, &buflen,
				&alloc_len);
	}
#endif

	if (bitmap & (1ULL << FATTR4_HIDDEN)) {
		INC32(attr->hidden ? 1 : 0);
	}
	if (bitmap & (1ULL << FATTR4_HOMOGENEOUS)) {
		INC32(attr->homogeneous ? 1 : 0);
	}
	if (bitmap & (1ULL << FATTR4_MAXFILESIZE)) {
		INC64(attr->maxfilesize);
	}
	if (bitmap & (1ULL << FATTR4_MAXLINK)) {
		INC32(attr->maxlink);
	}
	if (bitmap & (1ULL << FATTR4_MAXNAME)) {
		INC32(attr->maxname);
	}
	if (bitmap & (1ULL << FATTR4_MAXREAD)) {
		INC64(attr->maxread);
	}
	if (bitmap & (1ULL << FATTR4_MAXWRITE)) {
		INC64(attr->maxwrite);
	}
	if ((bitmap & (1ULL << FATTR4_MIMETYPE)) && (attr->mimetype.len)) {
		INCBUF(&attr->mimetype);
	}
	if (bitmap & (1ULL << FATTR4_MODE)) {
		INC32(attr->mode);
	}
	if (bitmap & (1ULL << FATTR4_NO_TRUNC)) {
		INC32(attr->no_trunc ? 1 : 0);
	}
	if (bitmap & (1ULL << FATTR4_NUMLINKS)) {
		INC32(attr->numlinks);
	}
	if ((bitmap & (1ULL << FATTR4_OWNER)) && (attr->owner.len)) {
		INCBUF(&attr->owner);
	}
	if ((bitmap & (1ULL << FATTR4_OWNER_GROUP)) && (attr->owner_group.len)){
		INCBUF(&attr->owner_group);
	}
	if (bitmap & (1ULL << FATTR4_QUOTA_AVAIL_HARD)) {
		INC64(attr->quota_avail_hard);
	}
	if (bitmap & (1ULL << FATTR4_QUOTA_AVAIL_SOFT)) {
		INC64(attr->quota_avail_soft);
	}
	if (bitmap & (1ULL << FATTR4_QUOTA_USED)) {
		INC64(attr->quota_used);
	}
	if (bitmap & (1ULL << FATTR4_RAWDEV)) {
		/* FIXME: correct order of these two dwords? */
		INC32(attr->rawdev.specdata1);
		INC32(attr->rawdev.specdata2);
	}
	if (bitmap & (1ULL << FATTR4_SPACE_AVAIL)) {
		INC64(attr->space_avail);
	}
	if (bitmap & (1ULL << FATTR4_SPACE_FREE)) {
		INC64(attr->space_free);
	}
	if (bitmap & (1ULL << FATTR4_SPACE_TOTAL)) {
		INC64(attr->space_total);
	}
	if (bitmap & (1ULL << FATTR4_SPACE_USED)) {
		INC64(attr->space_used);
	}
	if (bitmap & (1ULL << FATTR4_SYSTEM)) {
		INC32(attr->system ? 1 : 0);
	}
	if (bitmap & (1ULL << FATTR4_TIME_ACCESS)) {
		INC64(attr->time_access.seconds);
		INC32(attr->time_access.nseconds);
	}
	if (bitmap & (1ULL << FATTR4_TIME_BACKUP)) {
		INC64(attr->time_backup.seconds);
		INC32(attr->time_backup.nseconds);
	}
	if (bitmap & (1ULL << FATTR4_TIME_CREATE)) {
		INC64(attr->time_create.seconds);
		INC32(attr->time_create.nseconds);
	}
	if (bitmap & (1ULL << FATTR4_TIME_DELTA)) {
		INC64(attr->time_delta.seconds);
		INC32(attr->time_delta.nseconds);
	}
	if (bitmap & (1ULL << FATTR4_TIME_METADATA)) {
		INC64(attr->time_metadata.seconds);
		INC32(attr->time_metadata.nseconds);
	}
	if (bitmap & (1ULL << FATTR4_TIME_MODIFY)) {
		INC64(attr->time_modify.seconds);
		INC32(attr->time_modify.nseconds);
	}
	if (bitmap & (1ULL << FATTR4_MOUNTED_ON_FILEID)) {
		INC64(attr->mounted_on_fileid);
	}

	return total;
}

nfsstat4 cur_readattr(struct curbuf *cur, struct nfs_fattr_set *attr)
{
	uint64_t bitmap;
	uint32_t attr_len;
	nfsstat4 status = NFS4_OK;
	unsigned int start_len, end_len;

	memset(attr, 0, sizeof(*attr));

	attr->bitmap = bitmap = CURMAP();
	attr_len = CR32();	/* attribute buffer length */

	if (bitmap && (attr_len < 4))
		return NFS4ERR_BADXDR;

	if (bitmap & ~fattr_supported_mask)
		return NFS4ERR_ATTRNOTSUPP;

	start_len = cur->len;

	if (bitmap & (1ULL << FATTR4_SUPPORTED_ATTRS)) {
		attr->supported_attrs = CURMAP();
	}
	if (bitmap & (1ULL << FATTR4_TYPE)) {
		attr->type = CR32();
	}
	if (bitmap & (1ULL << FATTR4_FH_EXPIRE_TYPE)) {
		attr->fh_expire_type = CR32();
	}
	if (bitmap & (1ULL << FATTR4_CHANGE)) {
		attr->change = CR64();
	}
	if (bitmap & (1ULL << FATTR4_SIZE)) {
		attr->size = CR64();
	}
	if (bitmap & (1ULL << FATTR4_LINK_SUPPORT)) {
		attr->link_support = CR32();
	}
	if (bitmap & (1ULL << FATTR4_SYMLINK_SUPPORT)) {
		attr->symlink_support = CR32();
	}
	if (bitmap & (1ULL << FATTR4_NAMED_ATTR)) {
		attr->named_attr = CR32();
	}
	if (bitmap & (1ULL << FATTR4_FSID)) {
		attr->fsid.major = CR64();
		attr->fsid.minor = CR64();
	}
	if (bitmap & (1ULL << FATTR4_UNIQUE_HANDLES)) {
		attr->unique_handles = CR32();
	}
	if (bitmap & (1ULL << FATTR4_LEASE_TIME)) {
		attr->lease_time = CR32();
	}
	if (bitmap & (1ULL << FATTR4_RDATTR_ERROR)) {
		attr->rdattr_error = CR32();
	}
	if (bitmap & (1ULL << FATTR4_ACL)) {
		status = cur_readacl(cur, &attr->acl);
		if (status != NFS4_OK)
			goto out;
	}
	if (bitmap & (1ULL << FATTR4_ACLSUPPORT)) {
		attr->aclsupport = CR32();
	}
	if (bitmap & (1ULL << FATTR4_ARCHIVE)) {
		attr->archive = CR32();
	}
	if (bitmap & (1ULL << FATTR4_CANSETTIME)) {
		attr->cansettime = CR32();
	}
	if (bitmap & (1ULL << FATTR4_CASE_INSENSITIVE)) {
		attr->case_insensitive = CR32();
	}
	if (bitmap & (1ULL << FATTR4_CASE_PRESERVING)) {
		attr->case_preserving = CR32();
	}
	if (bitmap & (1ULL << FATTR4_CHOWN_RESTRICTED)) {
		attr->chown_restricted = CR32();
	}
	if (bitmap & (1ULL << FATTR4_FILEHANDLE)) {
		if (CR32() == 4)
			attr->filehandle = CR32();
		else
			status = NFS4ERR_BADXDR;
	}
	if (bitmap & (1ULL << FATTR4_FILEID)) {
		attr->fileid = CR64();
	}
	if (bitmap & (1ULL << FATTR4_FILES_AVAIL)) {
		attr->files_avail = CR64();
	}
	if (bitmap & (1ULL << FATTR4_FILES_FREE)) {
		attr->files_free = CR64();
	}
	if (bitmap & (1ULL << FATTR4_FILES_TOTAL)) {
		attr->files_total = CR64();
	}

#if FS_LOCATIONS_CODE_WORKING
	if (bitmap & (1ULL << FATTR4_FS_LOCATIONS)) {
		encode_pathname(&attr->fs_locations.fs_root, &buf, &p, &buflen,
				&alloc_len);
	}
#endif

	if (bitmap & (1ULL << FATTR4_HIDDEN)) {
		attr->hidden = CR32();
	}
	if (bitmap & (1ULL << FATTR4_HOMOGENEOUS)) {
		attr->homogeneous = CR32();
	}
	if (bitmap & (1ULL << FATTR4_MAXFILESIZE)) {
		attr->maxfilesize = CR64();
	}
	if (bitmap & (1ULL << FATTR4_MAXLINK)) {
		attr->maxlink = CR32();
	}
	if (bitmap & (1ULL << FATTR4_MAXNAME)) {
		attr->maxname = CR32();
	}
	if (bitmap & (1ULL << FATTR4_MAXREAD)) {
		attr->maxread = CR64();
	}
	if (bitmap & (1ULL << FATTR4_MAXWRITE)) {
		attr->maxwrite = CR64();
	}
	if (bitmap & (1ULL << FATTR4_MIMETYPE)) {
		CURBUF(&attr->mimetype);
		if (attr->mimetype.len &&
		    !g_utf8_validate(attr->mimetype.val,
		    		     attr->mimetype.len, NULL))
			status = NFS4ERR_INVAL;
	}
	if (bitmap & (1ULL << FATTR4_MODE)) {
		attr->mode = CR32();
	}
	if (bitmap & (1ULL << FATTR4_NO_TRUNC)) {
		attr->no_trunc = CR32();
	}
	if (bitmap & (1ULL << FATTR4_NUMLINKS)) {
		attr->numlinks = CR32();
	}
	if (bitmap & (1ULL << FATTR4_OWNER)) {
		CURBUF(&attr->owner);
		if (attr->owner.len &&
		    !g_utf8_validate(attr->owner.val, attr->owner.len, NULL))
			status = NFS4ERR_INVAL;
	}
	if (bitmap & (1ULL << FATTR4_OWNER_GROUP)) {
		CURBUF(&attr->owner_group);
		if (attr->owner_group.len &&
		    !g_utf8_validate(attr->owner_group.val,
		    		     attr->owner_group.len, NULL))
			status = NFS4ERR_INVAL;
	}
	if (bitmap & (1ULL << FATTR4_QUOTA_AVAIL_HARD)) {
		attr->quota_avail_hard = CR64();
	}
	if (bitmap & (1ULL << FATTR4_QUOTA_AVAIL_SOFT)) {
		attr->quota_avail_soft = CR64();
	}
	if (bitmap & (1ULL << FATTR4_QUOTA_USED)) {
		attr->quota_used = CR64();
	}
	if (bitmap & (1ULL << FATTR4_RAWDEV)) {
		/* FIXME: correct order of these two dwords? */
		attr->rawdev.specdata1 = CR32();
		attr->rawdev.specdata2 = CR32();
	}
	if (bitmap & (1ULL << FATTR4_SPACE_AVAIL)) {
		attr->space_avail = CR64();
	}
	if (bitmap & (1ULL << FATTR4_SPACE_FREE)) {
		attr->space_free = CR64();
	}
	if (bitmap & (1ULL << FATTR4_SPACE_TOTAL)) {
		attr->space_total = CR64();
	}
	if (bitmap & (1ULL << FATTR4_SPACE_USED)) {
		attr->space_used = CR64();
	}
	if (bitmap & (1ULL << FATTR4_SYSTEM)) {
		attr->system = CR32();
	}
	if (bitmap & (1ULL << FATTR4_TIME_ACCESS)) {
		attr->time_access.seconds = CR64();
		attr->time_access.nseconds = CR32();
	}
	if (bitmap & (1ULL << FATTR4_TIME_ACCESS_SET)) {
		if (CR32() == SET_TO_CLIENT_TIME4) {
			attr->time_access_set.seconds = CR64();
			attr->time_access_set.nseconds = CR32();
		} else {
			attr->time_access_set.seconds = current_time.tv_sec;
			attr->time_access_set.nseconds = 0;
		}
	}
	if (bitmap & (1ULL << FATTR4_TIME_BACKUP)) {
		attr->time_backup.seconds = CR64();
		attr->time_backup.nseconds = CR32();
	}
	if (bitmap & (1ULL << FATTR4_TIME_CREATE)) {
		attr->time_create.seconds = CR64();
		attr->time_create.nseconds = CR32();
	}
	if (bitmap & (1ULL << FATTR4_TIME_DELTA)) {
		attr->time_delta.seconds = CR64();
		attr->time_delta.nseconds = CR32();
	}
	if (bitmap & (1ULL << FATTR4_TIME_METADATA)) {
		attr->time_metadata.seconds = CR64();
		attr->time_metadata.nseconds = CR32();
	}
	if (bitmap & (1ULL << FATTR4_TIME_MODIFY)) {
		attr->time_modify.seconds = CR64();
		attr->time_modify.nseconds = CR32();
	}
	if (bitmap & (1ULL << FATTR4_TIME_MODIFY_SET)) {
		if (CR32() == SET_TO_CLIENT_TIME4) {
			attr->time_modify_set.seconds = CR64();
			attr->time_modify_set.nseconds = CR32();
		} else {
			attr->time_modify_set.seconds = current_time.tv_sec;
			attr->time_modify_set.nseconds = 0;
		}
	}
	if (bitmap & (1ULL << FATTR4_MOUNTED_ON_FILEID)) {
		attr->mounted_on_fileid = CR64();
	}

	end_len = cur->len;

	if (attr_len != (start_len - end_len))
		status = NFS4ERR_BADXDR;

out:
	return status;
}

nfsstat4 wr_fattr(const struct nfs_fattr_set *attr, uint64_t *_bitmap_out,
		  struct list_head *writes, struct rpc_write **wr)
{
	uint64_t bitmap = attr->bitmap;
	uint64_t bitmap_out = 0;
	uint32_t *bmap[2];
	uint32_t attr_size;

	WR32(2);		/* bitmap array size */
	bmap[0] = WRSKIP(4);	/* bitmap array[0] */
	bmap[1] = WRSKIP(4);	/* bitmap array[1] */

	attr_size = fattr_size(attr);
	WR32(attr_size);

	if (bitmap & (1ULL << FATTR4_SUPPORTED_ATTRS)) {
		WRMAP(fattr_supported_mask);
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

#if 0
	if (bitmap & (1ULL << FATTR4_ACL)) {
		encode_acl(&attr->acl, writes, wr);
		bitmap_out |= (1ULL << FATTR4_ACL);
	}
#endif

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
		WR32(4);
		WR32(attr->filehandle);
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
	if ((bitmap & (1ULL << FATTR4_MIMETYPE)) && (attr->mimetype.len)) {
		WRBUF(&attr->mimetype);
		bitmap_out |= (1ULL << FATTR4_MIMETYPE);
	}
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
	if ((bitmap & (1ULL << FATTR4_OWNER)) && (attr->owner.len)) {
		WRBUF(&attr->owner);
		bitmap_out |= (1ULL << FATTR4_OWNER);
	}
	if ((bitmap & (1ULL << FATTR4_OWNER_GROUP)) && (attr->owner_group.len)){
		WRBUF(&attr->owner_group);
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

	*bmap[0] = htonl(bitmap_out);
	*bmap[1] = htonl(bitmap_out >> 32);

	return NFS4_OK;
}

void fattr_free(struct nfs_fattr_set *attr)
{
	/* FIXME */
}

static void fattr_fill_server(struct nfs_fattr_set *attr)
{
	attr->lease_time = srv.lease_time;
}

static void fattr_fill_fs(struct nfs_fattr_set *attr)
{
	attr->supported_attrs = fattr_supported_mask;
	attr->fh_expire_type = SRV_FH_EXP_TYPE;
	attr->link_support = true;
	attr->symlink_support = true;
	attr->unique_handles = true;
	attr->cansettime = true;
	attr->case_insensitive = false;
	attr->case_preserving = true;
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
	attr->files_free = 33000000ULL;
	attr->files_total = g_hash_table_size(srv.inode_table) +
			    attr->files_free;

	attr->space_avail =
	attr->space_free = 400000000ULL;
	attr->space_total = srv.space_used + attr->space_free;
}

static void fattr_fill_obj(const struct nfs_inode *ino, struct nfs_fattr_set *attr)
{
	attr->type = ino->type;
	attr->change = ino->version;
	attr->size = ino->size;
	attr->space_used = ino->size;
	attr->named_attr = false;
	attr->fsid.major = 1;
	attr->fsid.minor = 0;
	attr->rdattr_error = NFS4_OK;
	attr->filehandle = ino->ino;
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

	attr->owner.val = ino->user;
	attr->owner.len = strlen(ino->user);
	attr->owner_group.val = ino->group;
	attr->owner_group.len = strlen(ino->group);

	attr->mounted_on_fileid = ino->ino;
}

void fattr_fill(const struct nfs_inode *ino, struct nfs_fattr_set *attr)
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

void print_fattr(const char *pfx, const struct nfs_fattr_set *attr)
{
	print_fattr_bitmap(pfx, attr->bitmap);
}


