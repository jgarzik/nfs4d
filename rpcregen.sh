#!/bin/sh

# WARNING:  manual mods required after running this

rm -f nfs4_xdr.c ; rpcgen -C -M -c -o nfs4_xdr.c nfs4_prot.x 
rm -f nfs4_prot.h ; rpcgen -C -M -h -o nfs4_prot.h nfs4_prot.x 
rm -f fsdb_xdr.c ; rpcgen -C -M -c -o fsdb_xdr.c fsdb_xdr.x
rm -f fsdb_xdr.h ; rpcgen -C -M -h -o fsdb_xdr.h fsdb_xdr.x
