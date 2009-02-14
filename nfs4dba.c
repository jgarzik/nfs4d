
#define _GNU_SOURCE
#include "nfs4d-config.h"
#include <stdio.h>
#include <string.h>
#include <locale.h>
#include <argp.h>
#include <glib.h>
#include "fsdb.h"
#include "nfscommon.h"

enum pgmmodes {
	mode_none,
	mode_store_root,
};

static char *opt_lcldom = "localdomain";

static char *opt_data_path = "/tmp/data/";
static char *opt_metadata = "/tmp/metadata/";
static enum pgmmodes pmode = mode_none;

static int debugging;
static struct fsdb fsdb;

static const char doc[] =
"nfs4dba - NFS4 server database administration";

static struct argp_option options[] = {
	{ "metadata", 'M', "DIRECTORY", 0,
	  "Metadata directory" },
	{ "data", 'D', "DIRECTORY", 0,
	  "Data directory" },

	{ "debug", 'd', "LEVEL", 0,
	  "Enable debug output (def. 0 = no debug, 2 = maximum debug output)" },

	{ "localdomain", 'O', "DOMAIN", 0,
	  "Local domain (def: gethostname; used with user/group ids, required by NFS)" },

	{ "store-root", 'R', NULL, 0,
	  "Initialize FS, by storing (overwriting) root inode default data" },

	{ }
};

static error_t parse_opt (int key, char *arg, struct argp_state *state);
static const struct argp argp = { options, parse_opt, NULL, doc };

static int store_root(void)
{
	int rc;
	struct fsdb_inode *ino;
	size_t ino_size = sizeof(*ino);
	char *user, *group;
	void *p;

	asprintf(&user, "root@%s", opt_lcldom);
	asprintf(&group, "root@%s", opt_lcldom);

	ino = alloca(256);
	memset(ino, 0, 256);

	p = ino;
	p += sizeof(*ino);

	ino->inum = GUINT64_TO_LE(INO_ROOT);
	ino->version = GUINT64_TO_LE(1);
	ino->size = GUINT64_TO_LE(4096);
	ino->ctime =
	ino->atime =
	ino->mtime = GUINT64_TO_LE(current_time.tv_sec);
	ino->ftype = GUINT32_TO_LE(NF4DIR);
	ino->mode = GUINT32_TO_LE(0755);
	ino->n_link = GUINT32_TO_LE(1);
	ino->user_len = GUINT16_TO_LE(strlen(user));
	ino->group_len = GUINT16_TO_LE(strlen(group));

	memcpy(p, user, strlen(user));
	p += strlen(user);

	memcpy(p, group, strlen(group));

	ino_size += strlen(user) + strlen(group);

	rc = fsdb_inode_put(&fsdb, NULL, ino, ino_size, 0);
	if (rc) {
		fprintf(stderr, "error storing root inode\n");
		return 1;
	}
	
	fprintf(stderr, "root inode stored successfully\n");
	return 0;
}

static error_t parse_opt (int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'd':
		if (atoi(arg) >= 0 && atoi(arg) <= 2)
			debugging = atoi(arg);
		else {
			fprintf(stderr, "invalid debug level %s (valid: 0-2)\n",
				arg);
			argp_usage(state);
		}
		break;
	case 'D':
		if (!is_dir(arg, &opt_data_path))
			argp_usage(state);
		break;
	case 'M':
		if (!is_dir(arg, &opt_metadata))
			argp_usage(state);
		break;
	case 'O':
		opt_lcldom = arg;
		break;

	case 'R':
		pmode = mode_store_root;
		break;

	case ARGP_KEY_ARG:
		argp_usage(state);	/* too many args */
		break;

	case ARGP_KEY_END:
		break;

	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

int main (int argc, char *argv[])
{
	struct timezone tz = { 0, 0 };
	error_t aprc;
	int rc;

	setlocale(LC_ALL, "");

	aprc = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (aprc) {
		fprintf(stderr, "argp_parse failed: %s\n", strerror(aprc));
		return 1;
	}

	gettimeofday(&current_time, &tz);

	memset(&fsdb, 0, sizeof(fsdb));
	fsdb.home = opt_metadata;

	rc = fsdb_open(&fsdb, DB_RECOVER | DB_CREATE, DB_CREATE,
		       "nfs4dba", false);
	if (rc)
		return 1;

	switch (pmode) {
	case mode_store_root:
		return store_root();

	default:
		break;
	}

	fsdb_close(&fsdb);

	return 1;
}

