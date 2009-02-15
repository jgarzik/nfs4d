
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
#include <stdlib.h>
#include <pwd.h>
#include <grp.h>
#include "server.h"

char *id_lookup(enum id_type type, uint32_t id)
{
	char *s, *rstr;

	if (type == idt_user) {
		struct passwd *pw = getpwuid(id);
		if (!pw)
			return NULL;

		s = pw->pw_name;
	} else {
		struct group *gr = getgrgid(id);
		if (!gr)
			return NULL;

		s = gr->gr_name;
	}
		
	if (asprintf(&rstr, "%s@%s", s, srv.localdom) < 0)
		rstr = NULL;

	return rstr;
}

char *id_lookup_name(enum id_type type, const char *name_in, size_t name_len)
{
	char *s, *rstr = NULL, *name, *dom;

	name = copy_binstr(name_in, name_len);
	if (!name)
		return NULL;

	dom = strchr(name, '@');
	if (dom) {
		/* truncate 'name' before '@' */
		*dom = 0;
		dom++;

		/* verify that domain names match */
		if (strcmp(dom, srv.localdom))
			return NULL;
	}

	if (type == idt_user) {
		struct passwd *pw = getpwnam(name);
		if (!pw)
			goto out;

		s = pw->pw_name;
	} else {
		struct group *gr = getgrnam(name);
		if (!gr)
			goto out;

		s = gr->gr_name;
	}
		
	if (asprintf(&rstr, "%s@%s", s, srv.localdom) < 0)
		rstr = NULL;

out:
	free(name);
	return rstr;
}

