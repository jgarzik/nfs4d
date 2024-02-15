
EXTRA_DIST =		\
	prep-db		\
	clean-db	\
	start-daemon	\
	stop-daemon	\
	pid-exists

TESTS =			\
	prep-db		\
	start-daemon	\
	pid-exists	\
	null		\
	basic		\
	getattr		\
	getattr-statfs	\
	stop-daemon	\
	clean-db

noinst_PROGRAMS =	\
	null		\
	basic		\
	getattr		\
	getattr-statfs

noinst_LIBRARIES = libnfstest.a

libnfstest_a_SOURCES = nfstest.h nfs4_compat.h nfs4_prot.h nfs4_prot_clnt.c nfs4_prot_client.c nfs4_prot_xdr.c

null_LDADD		= libnfstest.a @TIRPC_LIBS@
basic_LDADD		= libnfstest.a @TIRPC_LIBS@
getattr_LDADD		= libnfstest.a @TIRPC_LIBS@
getattr_statfs_LDADD	= libnfstest.a @TIRPC_LIBS@

TESTS_ENVIRONMENT=top_srcdir=$(top_srcdir)

