##
## Toplevel Makefile.am
##

SUBDIRS		= test

INCLUDES	= @GNET_CFLAGS@

sbin_PROGRAMS	= nfs4d

nfs4d_SOURCES	= elist.h nfs4_prot.h server.h fattr.h \
		  main.c server.c			\
		  dir.c fh.c fattr.c inode.c open.c	\
		  id.c state.c data.c
nfs4d_LDADD	= @GNET_LIBS@

EXTRA_DIST	= autogen.sh nfs4_prot.x

