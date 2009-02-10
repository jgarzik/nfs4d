
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

#define _GNU_SOURCE
#include "nfs4d-config.h"
#include <sys/types.h>
#include <string.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <syslog.h>
#include <glib.h>
#include "server.h"
#include "elist.h"

static GHashTable *tbl_users;
static GHashTable *tbl_groups;

static int tbl_add(GHashTable *tbl, const char *name_in, unsigned int id)
{
	char *name = NULL;

	if (asprintf(&name, "%s@localdomain", name_in) < 0) {
		syslog(LOG_ERR, "OOM in tbl_add");
		return -ENOMEM;
	}

	/* to avoid being confused with NULL, we assume
	 * 0xffffffff is root@localdomain
	 */
	if (!id)
		id = 0xffffffff;

	g_hash_table_insert(tbl, GUINT_TO_POINTER(id), name);

	return 0;
}

static int read_users(void)
{
	int rc = 0;

	setpwent();

	while (1) {
		struct passwd *pw;

		errno = 0;
		pw = getpwent();
		if (errno) {
			rc = -errno;
			syslogerr("getpwent");
			break;
		}
		if (!pw)
			break;

		rc = tbl_add(tbl_users, pw->pw_name, pw->pw_uid);
		if (rc)
			break;
	}

	endpwent();

	return rc;
}

static int read_groups(void)
{
	int rc = 0;

	setgrent();

	while (1) {
		struct group *gr;

		errno = 0;
		gr = getgrent();
		if (errno) {
			rc = -errno;
			syslogerr("getgrent");
			break;
		}
		if (!gr)
			break;

		rc = tbl_add(tbl_groups, gr->gr_name, gr->gr_gid);
		if (rc)
			break;
	}

	endgrent();

	return rc;
}

int id_init(void)
{
	int rc;

	tbl_users = g_hash_table_new_full(g_direct_hash, g_direct_equal,
					  NULL, free);
	tbl_groups = g_hash_table_new_full(g_direct_hash, g_direct_equal,
					   NULL, free);

	if (!tbl_users || !tbl_groups)
		return -ENOMEM;

	rc = read_users();
	if (rc)
		return rc;

	rc = read_groups();
	if (rc)
		return rc;

	return 0;
}

char *id_lookup(enum id_type type, unsigned int id)
{
	return g_hash_table_lookup(type == idt_user ? tbl_users : tbl_groups,
				   GUINT_TO_POINTER(id));
}

struct name_search_info {
	const char	*name;
	size_t		name_len;
	char		*match;
};

static void name_search_iter(gpointer key, gpointer val, gpointer user_data)
{
	char *name = val;
	struct name_search_info *nsi = user_data;

	if ((strlen(name) == nsi->name_len) &&
	    !memcmp(name, nsi->name, nsi->name_len))
		nsi->match = name;
}

char *id_lookup_name(enum id_type type, const char *name, size_t name_len)
{
	struct name_search_info nsi = { name, name_len, NULL };
	g_hash_table_foreach(type == idt_user ? tbl_users : tbl_groups,
			     name_search_iter, &nsi);

	return nsi.match;
}

