#define _GNU_SOURCE
#include "nfs4-ram-config.h"
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
	char *name = strdup(name_in);

	if (!name) {
		syslog(LOG_ERR, "OOM in tbl_add");
		return -ENOMEM;
	}

	if (!id)
		id = 0xffffffff;

	g_hash_table_insert(tbl, name, GUINT_TO_POINTER(id));

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

	tbl_users = g_hash_table_new_full(g_str_hash, g_str_equal,
					  free, NULL);
	tbl_groups = g_hash_table_new_full(g_str_hash, g_str_equal,
					  free, NULL);

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

struct id_lookup_info {
	unsigned int	id;
	char		*name;
};

static void id_lookup_iter(gpointer key, gpointer val, gpointer user_data)
{
	unsigned int id = (unsigned long) val;
	struct id_lookup_info *info = user_data;

	if (id == info->id)
		info->name = key;
}

char *id_lookup(enum id_type type, unsigned int id)
{
	struct id_lookup_info info = { id, NULL };

	/* FIXME: this is stupid.  we originally used a hash table
	 * due to name-lookup requirements, now we just iterate through
	 * its values
	 */

	g_hash_table_foreach(type == idt_user ? tbl_users : tbl_groups,
			     id_lookup_iter,
			     &info);

	return info.name;
}

