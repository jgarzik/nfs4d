#include <rpc/xdr.h>
#include <glib.h>
#include "nfs4_prot.h"
#include "server.h"

enum {
	FATTR_LAST		= FATTR4_MOUNTED_ON_FILEID,
};

static size_t raw_pathname_size(pathname4 *path)
{
	size_t s;
	unsigned int i;

	s = path->pathname4_len * sizeof(component4);

	for (i = 0; i < path->pathname4_len; i++)
		s += path->pathname4_val[i].utf8string_len;

	return s;
}

#define FATTR_DEFINE(a,b,c)				\
	if (bitmap & ( 1ULL << FATTR4_##a ))		\
		s += sizeof(attr->b);

static size_t raw_fattr_size(guint64 bitmap, struct nfs_fattr_set *attr)
{
	size_t s = 0;
	unsigned int i;

#include "fattr.h"

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

#undef FATTR_DEFINE

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

	/* FIXME: set bitmap4 attrmask */

	raw->attr_vals.attrlist4_len = buflen;
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

	/* raw->attr_vals.attrlist4_val; */

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
	/* FIXME? */
}

