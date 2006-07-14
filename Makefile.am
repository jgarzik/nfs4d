##
## Toplevel Makefile.am
##

INCLUDES	= @GLIB_CFLAGS@

sbin_PROGRAMS	= nfs4_ramd

nfs4_ramd_SOURCES = nfs4_prot.h nfs4_prot_xdr.c \
		nfs4_prot_server.c nfs4_prot_svc.c
nfs4_ramd_LDADD = @GLIB_LIBS@ @GSSRPC_LIBS@

EXTRA_DIST	= autogen.sh nfs4_prot.x

