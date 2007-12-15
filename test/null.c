
#include <stdlib.h>
#include <unistd.h>
#include "nfs4_prot.h"
#include "nfstest.h"

void test(CLIENT *clnt)
{
	void  *result_1;
	char *nfsproc4_null_4_arg;

	result_1 = nfsproc4_null_4((void*)&nfsproc4_null_4_arg, clnt);
	if (result_1 == (void *) NULL)
		exit(1);

	result_1 = nfsproc4_null_4((void*)&nfsproc4_null_4_arg, clnt);
	if (result_1 == (void *) NULL)
		exit(1);

	exit(0);
}

