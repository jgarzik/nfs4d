##
## Toplevel Makefile.am
##

SUBDIRS		= doc test

AM_CPPFLAGS	= @GLIB_CFLAGS@

noinst_LIBRARIES= libnfscommon.a

sbin_PROGRAMS	= nfs4d nfs4dba

libnfscommon_a_SOURCES = util.c db.c fsdb_xdr.h fsdb_xdr.c nfs4_xdr.c

nfs4d_SOURCES	= nfscommon.h elist.h nfs4_prot.h server.h fattr.h fsdb.h \
		  main.c server.c			\
		  dir.c fh.c fattr.c inode.c open.c	\
		  id.c state.c data.c
nfs4d_LDADD	= libnfscommon.a @GLIB_LIBS@ @DB4_LIBS@ @EVENT_LIBS@ @ARGP_LIBS@ @TIRPC_LIBS@

nfs4dba_LDADD	= libnfscommon.a @GLIB_LIBS@ @DB4_LIBS@ @ARGP_LIBS@ @TIRPC_LIBS@

EXTRA_DIST	= autogen.sh nfs4_prot.x

