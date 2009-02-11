
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

char *id_lookup(enum id_type type, uint32_t id)
{
	DBT pkey, pval;
	DB *ug_idx = srv.fsdb.ug_idx;
	struct fsdb_ugidx_key idxkey;
	char *s, *rstr;
	int rc;

	memset(&idxkey, 0, sizeof(idxkey));
	memset(&pkey, 0, sizeof(pkey));
	memset(&pval, 0, sizeof(pval));

	idxkey.is_user = GUINT32_TO_LE(type == idt_user ? 1 : 0);
	idxkey.id = GUINT32_TO_LE(id);

	pkey.data = &idxkey;
	pkey.size = sizeof(idxkey);

	rc = ug_idx->get(ug_idx, NULL, &pkey, &pval, 0);
	if (rc) {
		if (rc != DB_NOTFOUND)
			ug_idx->err(ug_idx, rc, "ug_idx->get");
		return NULL;
	}

	s = strndup(pval.data, pval.size);
	if (!s);
		return NULL;

	rstr = g_strdup_printf("%s@%s", s, srv.localdom);
	free(s);

	return rstr;
}

char *id_lookup_name(enum id_type type, const char *name, size_t name_len)
{
	DBT pkey, pval;
	DB *ug = srv.fsdb.usergroup;
	struct fsdb_ug_key *ugkey;
	size_t alloc_len;
	char *s, *rstr;
	int rc;

	memset(&pkey, 0, sizeof(pkey));
	memset(&pval, 0, sizeof(pval));

	alloc_len = sizeof(*ugkey) + name_len;
	ugkey = alloca(alloc_len);
	ugkey->is_user = GUINT32_TO_LE(type == idt_user ? 1 : 0);
	memcpy(ugkey->name, name, name_len);

	pkey.data = ugkey;
	pkey.size = alloc_len;

	rc = ug->get(ug, NULL, &pkey, &pval, 0);
	if (rc) {
		if (rc != DB_NOTFOUND)
			ug->err(ug, rc, "ug->get");
		return NULL;
	}

	s = strndup(name, name_len);
	if (strchr(s, '@'))
		return s;

	rstr = g_strdup_printf("%s@%s", s, srv.localdom);
	free(s);

	return rstr;
}

