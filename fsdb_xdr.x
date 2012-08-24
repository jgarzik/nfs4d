
/*
 * Copyright 2012 Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING.  If not, write to
 * the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

/*
 * Basic typedefs for RFC 1832 data type definitions
 */

typedef int			int32_t;
typedef unsigned int		uint32_t;
typedef hyper			int64_t;
typedef unsigned hyper		uint64_t;

const NFS_VERIFIER_SIZE	= 8;
const NFS_OPAQUE_LIMIT	= 1024;

typedef uint64_t	fsdb_client_id;

struct fsdb_client {
	fsdb_client_id	id;
	uint32_t	flags;
	opaque		verifier[NFS_VERIFIER_SIZE];
	opaque		owner<NFS_OPAQUE_LIMIT>;
};

