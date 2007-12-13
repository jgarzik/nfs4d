##
## Toplevel Makefile.am
##

INCLUDES	= @GNET_CFLAGS@

sbin_PROGRAMS	= nfs4_ramd

nfs4_ramd_SOURCES = elist.h nfs4_prot.h server.h fattr.h \
		    main.c server.c			\
		    dir.c fh.c fattr.c inode.c open.c	\
		    state.c data.c
nfs4_ramd_LDADD = @GNET_LIBS@

EXTRA_DIST	= autogen.sh nfs4_prot.x

