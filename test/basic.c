
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "nfs4_prot.h"
#include "nfstest.h"

void test(CLIENT *clnt)
{
	COMPOUND4res  *res;
	COMPOUND4args  arg;
	nfs_argop4 args[2];
#if 0
	int i;
#endif

	memset(&arg, 0, sizeof(arg));
	arg.tag.utf8string_val = "blah";
	arg.tag.utf8string_len = strlen(arg.tag.utf8string_val);
	arg.minorversion = 0;
	arg.argarray.argarray_len = 2;
	arg.argarray.argarray_val = args;

	args[0].argop = OP_PUTROOTFH;

	args[1].argop = OP_LOOKUP;
	args[1].nfs_argop4_u.oplookup.objname.utf8string_val = "tmpXmissing";
	args[1].nfs_argop4_u.oplookup.objname.utf8string_len =
		strlen(args[1].nfs_argop4_u.oplookup.objname.utf8string_val);

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

	if (res->status != NFS4ERR_NOENT)
		exit(1);

	exit(0);
}
