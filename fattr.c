#include <glib.h>
#include "nfs4_prot.h"
#include "server.h"

enum {
	FATTR_LAST		= FATTR4_MOUNTED_ON_FILEID,
};

static void parse_i32(gchar **ptr_io, int32_t *val)
{
	int32_t *ptr = (int32_t *) *ptr_io;
	*val = GUINT32_FROM_BE(*ptr);
	*ptr_io += sizeof(int32_t);
}

static void parse_u32(gchar **ptr_io, uint32_t *val)
{
	parse_i32(ptr_io, (int32_t *) val);
}

static void parse_i64(gchar **ptr_io, uint64_t *val)
{
	uint64_t *ptr = (uint64_t *) *ptr_io;
	*val = GUINT64_FROM_BE(*ptr);
	*ptr_io += sizeof(int64_t);
}

static void parse_time(gchar **ptr_io, nfstime4 *val)
{
	parse_i64(ptr_io, (uint64_t *) &val->seconds);
	parse_u32(ptr_io, &val->nseconds);
}

struct nfs_blob {
	u_int len;
	char *val;
};

static void parse_blob(gchar **ptr_io, struct nfs_blob *blob)
{
	unsigned int len, tail;

	parse_u32(ptr_io, &blob->len);
	blob->val = *ptr_io;

	len = blob->len;
	tail = len & 0x3;
	if (tail)
		len += (4 - tail);

	*ptr_io += len;
}

static void parse_utf8(gchar **ptr_io, utf8string *val)
{
	parse_blob(ptr_io, (struct nfs_blob *) val);
}

static void parse_filehandle(gchar **ptr_io, nfs_fh4 *val)
{
	parse_blob(ptr_io, (struct nfs_blob *) val);
}

static void parse_nfsstat(gchar **ptr_io, nfsstat4 *val)
{
	parse_u32(ptr_io, (uint32_t *) val);
}

static void parse_settime(gchar **ptr_io, settime4 *val)
{
	parse_u32(ptr_io, (uint32_t *) &val->set_it);
	parse_time(ptr_io, &val->settime4_u.time);
}

static void parse_rawdev(gchar **ptr_io, specdata4 *val)
{
	parse_u32(ptr_io, &val->specdata1);
	parse_u32(ptr_io, &val->specdata2);
}

static void parse_type(gchar **ptr_io, nfs_ftype4 *val)
{
	parse_u32(ptr_io, (uint32_t *) val);
}

static void parse_fsid(gchar **ptr_io, fsid4 *val)
{
	parse_i64(ptr_io, &val->major);
	parse_i64(ptr_io, &val->minor);
}

static void parse_bitmap(gchar **ptr_io, bitmap4 *val)
{
	/* FIXME */
}

static void parse_acl(gchar **ptr_io, fattr4_acl *val)
{
	/* FIXME */
}

static void parse_fs_locations(gchar **ptr_io, fs_locations4 *val)
{
	/* FIXME */
}

#define FATTR_DEFINE(a,b,c)			\
	if (bitmap & ( 1ULL << FATTR4_##a ))	\
		parse_##c (&ptr, &attr->b);

bool_t fattr_parse(fattr4 *raw, struct nfs_fattr_set *attr)
{
	gchar *ptr;
	uint64_t bitmap = 0;

	memset(attr, 0, sizeof(*attr));
	if (raw->attrmask.bitmap4_len > 0)
		bitmap = raw->attrmask.bitmap4_val[0];
	if (raw->attrmask.bitmap4_len > 1)
		bitmap |= ((uint64_t)raw->attrmask.bitmap4_val[1]) << 32;
	attr->bitmap = bitmap;

	ptr = raw->attr_vals.attrlist4_val;

#include "fattr.h"

	return TRUE;
}

#undef FATTR_DEFINE

void fattr_free(struct nfs_fattr_set *attr)
{
}

