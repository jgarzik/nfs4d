##
## Toplevel Makefile.am
##

INCLUDES	= @GLIB_CFLAGS@

sbin_PROGRAMS	= nfs4_ramd

nfs4_ramd_SOURCES = nfs4_prot.h xdr.c main.c server.c
nfs4_ramd_LDADD = @GLIB_LIBS@ @GSSRPC_LIBS@

EXTRA_DIST	= autogen.sh nfs4_prot.x

