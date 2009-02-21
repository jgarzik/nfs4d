
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "nfs4_prot.h"
#include "nfstest.h"

void test(CLIENT *clnt)
{
	COMPOUND4res  *res;
	COMPOUND4args  arg;
	nfs_argop4 args[9];
	uint32_t bmap[2], attr_req[2];
	char dummy[4];
#if 0
	int i;
#endif

	memset(&arg, 0, sizeof(arg));
	memset(&args, 0, sizeof(args));

	arg.tag.utf8string_val = "blah";
	arg.tag.utf8string_len = strlen(arg.tag.utf8string_val);
	arg.minorversion = 0;
	arg.argarray.argarray_len = 3;
	arg.argarray.argarray_val = args;

	args[0].argop = OP_PUTROOTFH;

	args[1].argop = OP_CREATE;
	args[1].nfs_argop4_u.opcreate.objtype.type = NF4LNK;
	args[1].nfs_argop4_u.opcreate.objtype.createtype4_u.linkdata.utf8string_val =
		"/etc/X11";
	args[1].nfs_argop4_u.opcreate.objtype.createtype4_u.linkdata.utf8string_len =
		strlen(args[1].nfs_argop4_u.opcreate.objtype.createtype4_u.linkdata.utf8string_val);

	args[1].nfs_argop4_u.opcreate.objname.utf8string_val = "test";
	args[1].nfs_argop4_u.opcreate.objname.utf8string_len =
		strlen(args[1].nfs_argop4_u.opcreate.objname.utf8string_val);

	bmap[0] = 0;
	bmap[1] = 0;
	args[1].nfs_argop4_u.opcreate.createattrs.attrmask.bitmap4_len = 2;
	args[1].nfs_argop4_u.opcreate.createattrs.attrmask.bitmap4_val = bmap;

	args[1].nfs_argop4_u.opcreate.createattrs.attr_vals.attrlist4_len = 0;
	args[1].nfs_argop4_u.opcreate.createattrs.attr_vals.attrlist4_val = dummy;

	args[2].argop = OP_GETATTR;
	attr_req[0] =
		(1 << FATTR4_SUPPORTED_ATTRS);
	attr_req[1] = 0;
	args[2].nfs_argop4_u.opgetattr.attr_request.bitmap4_len = 2;
	args[2].nfs_argop4_u.opgetattr.attr_request.bitmap4_val = attr_req;

	res = nfsproc4_compound_4(&arg, clnt);
	if (res == (COMPOUND4res *) NULL)
		exit(1);

#if 0
	printf(	"COMPOUND result:\n"
		"status %s\n"
		"tag %.*s\n"
		"numres %u\n",
		name_nfs4status[res->status],
		res->tag.utf8string_len,
		res->tag.utf8string_val,
		res->resarray.resarray_len);

	for (i = 0; i < res->resarray.resarray_len; i++)
		print_resop(&res->resarray.resarray_val[i]);
#endif

	if (res->status != NFS4_OK)
		exit(1);

	exit(0);
}
