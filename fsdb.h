#ifndef __FSDB_H__
#define __FSDB_H__

/*
 * Copyright 2008-2009 Red Hat, Inc.
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


#include <stdbool.h>
#include <db.h>

struct fsdb_ug_key {
	uint32_t	is_user;
	char		name[0];
};

struct fsdb_ugidx_key {
	uint32_t	is_user;
	uint32_t	id;
};

struct fsdb {
	char		*home;			/* database home dir */
	char		*key;			/* database AES key */

	DB_ENV		*env;			/* db4 env ptr */
	DB		*inodes;		/* inodes */
	DB		*usergroup;		/* users/groups */
	DB		*ug_idx;		/* u/g index */
};


extern int fsdb_open(struct fsdb *fsdb, unsigned int env_flags,
	unsigned int flags, const char *errpfx, bool do_syslog);
extern void fsdb_close(struct fsdb *fsdb);

#endif /* __FSDB_H__ */
