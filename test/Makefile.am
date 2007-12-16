
EXTRA_DIST =		\
	start-daemon	\
	stop-daemon	\
	pid-exists

TESTS =			\
	start-daemon	\
	pid-exists	\
	null		\
	basic		\
	getattr		\
	getattr-statfs	\
	stop-daemon

noinst_PROGRAMS =	\
	null		\
	basic		\
	getattr		\
	getattr-statfs

noinst_LIBRARIES = libnfstest.a

libnfstest_a_SOURCES = nfstest.h nfs4_prot.h nfs4_prot_clnt.c nfs4_prot_client.c nfs4_prot_xdr.c

null_LDADD		= libnfstest.a
basic_LDADD		= libnfstest.a
getattr_LDADD		= libnfstest.a
getattr_statfs_LDADD	= libnfstest.a

TESTS_ENVIRONMENT=top_srcdir=$(top_srcdir)

