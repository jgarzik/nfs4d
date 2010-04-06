
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
#include <sys/stat.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <locale.h>
#include <argp.h>
#include <glib.h>
#include "fsdb.h"
#include "nfscommon.h"

#define PFX "nfs4dba: "

enum pgmmodes {
	mode_none,
	mode_init_fs,
	mode_show,
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

	{ "init-fs", 'I', NULL, 0,
	  "Initialize FS" },
	{ "show-data", 'S', NULL, 0,
	  "Display all data in database" },

	{ }
};

static error_t parse_opt (int key, char *arg, struct argp_state *state);
static const struct argp argp = { options, parse_opt, NULL, doc };

#if 0 /* will be used again soon */
static void dump_inode(FILE *f, const struct nfs_inode *ino)
{
	if (!ino)
		return;

	fprintf(f,
		"INODE: %016llX\n"
		"parent: %016llX\n"
		"type: %s\n"
		"version: %Lu\n"
		,
		(unsigned long long) ino->inum,
		(unsigned long long) ino->parent,
		name_nfs_ftype4[ino->type],
		(unsigned long long) ino->version);

	if (ino->ctime || ino->atime || ino->mtime)
		fprintf(f, "time: create %Lu access %Lu modify %Lu\n",
			(unsigned long long) ino->ctime,
			(unsigned long long) ino->atime,
			(unsigned long long) ino->mtime);
	if (ino->mode)
		fprintf(f, "mode: %o\n", ino->mode);
	if (ino->user)
		fprintf(f, "user: %s\n", ino->user);
	if (ino->group)
		fprintf(f, "group: %s\n", ino->group);
	if (ino->mimetype)
		fprintf(f, "mime-type: %s\n", ino->mimetype);

	switch (ino->type) {
	case NF4DIR:
		fprintf(f, "directory: TODO\n");	/* FIXME */
		break;
	case NF4LNK:
		fprintf(f, "linktext: %s\n", ino->linktext);
		break;
	case NF4BLK:
	case NF4CHR:
		fprintf(f, "devdata: %u %u\n", ino->devdata[0], ino->devdata[1]);
		break;
	case NF4REG:
		fprintf(f, "size: %Lu\n", (unsigned long long) ino->size);
		break;

	default:
		/* do nothing */
		break;
	}

	fprintf(f, "===========================\n");
}
#endif

static void inode_iter(const struct fsdb_inode *ino)
{
	const void *p;
	const char *user = "", *group = "", *mime = "", *link_txt = "";
	int user_len, group_len, mime_len, link_len;

	user_len = GUINT16_FROM_LE(ino->user_len);
	group_len = GUINT16_FROM_LE(ino->group_len);
	mime_len = GUINT16_FROM_LE(ino->type_len);
	link_len = GUINT16_FROM_LE(ino->link_len);

	p = ino;
	p += sizeof(*ino);

	if (user_len) {
		user = p;
		p += user_len;
	}
	if (group_len) {
		group = p;
		p += group_len;
	}
	if (mime_len) {
		mime = p;
		p += mime_len;
	}
	if (link_len) {
		link_txt = p;
		p += link_len;
	}

	printf(
	"INODE %016llX\n"
	"Parent %016llX\n"
	"Version %llu\n"
	"Size %llu\n"
	"ctime %llu\n"
	"atime %llu\n"
	"mtime %llu\n"

	"ftype %s\n"
	"mode %o\n"
	"n_link %u\n"
	"devdata %x %x\n"

	"user '%.*s'\n"
	"group '%.*s'\n"
	"mimetype '%.*s'\n"
	"linktext '%.*s'\n"
	"\n\n",

	(unsigned long long) inum_decode(ino->inum),
	(unsigned long long) inum_decode(ino->parent),
	(unsigned long long) GUINT64_FROM_LE(ino->version),
	(unsigned long long) GUINT64_FROM_LE(ino->size),
	(unsigned long long) GUINT64_FROM_LE(ino->ctime),
	(unsigned long long) GUINT64_FROM_LE(ino->atime),
	(unsigned long long) GUINT64_FROM_LE(ino->mtime),

	name_nfs_ftype4[GUINT32_FROM_LE(ino->ftype)],
	GUINT32_FROM_LE(ino->mode),
	GUINT32_FROM_LE(ino->n_link),
	GUINT32_FROM_LE(ino->devdata[0]),
	GUINT32_FROM_LE(ino->devdata[1]),

	user_len,
	user,
	group_len,
	group,
	mime_len,
	mime,
	link_len,
	link_txt);
}

static int show_inodes(void)
{
	DB_TXN *txn = NULL;
	DB *inodes = fsdb.inodes;
	DB_ENV *dbenv = fsdb.env;
	DBT pkey, pval;
	DBC *curs = NULL;
	int rc;

	/* open transaction */
	rc = dbenv->txn_begin(dbenv, NULL, &txn, 0);
	if (rc) {
		dbenv->err(dbenv, rc, "DB_ENV->txn_begin");
		goto out;
	}

	/* otherwise, loop through each inodes attached to ino->inum */
	rc = inodes->cursor(inodes, txn, &curs, 0);
	if (rc) {
		inodes->err(inodes, rc, "inodes->cursor");
		goto out_abort;
	}

	memset(&pkey, 0, sizeof(pkey));

	memset(&pval, 0, sizeof(pval));
	pval.flags = DB_DBT_MALLOC;

	while (1) {
		struct fsdb_inode *raw_ino;

		rc = curs->get(curs, &pkey, &pval, DB_NEXT);
		if (rc) {
			if (rc != DB_NOTFOUND)
				inodes->err(inodes, rc, "readdir curs->get");
			break;
		}

		raw_ino = pval.data;
		inode_iter(raw_ino);
		free(raw_ino);
	}

	rc = curs->close(curs);
	if (rc) {
		inodes->err(inodes, rc, "inodes->cursor close");
		goto out_abort;
	}

	/* close transaction */
	rc = txn->commit(txn, 0);
	if (rc) {
		dbenv->err(dbenv, rc, "DB_ENV->txn_commit");
		goto out;
	}

out:
	return 0;

out_abort:
	if (txn->abort(txn))
		dbenv->err(dbenv, rc, "DB_ENV->txn_abort");
	goto out;
}

static void readdir_iter(const struct fsdb_de_key *key,
			 size_t key_len, nfsino_t dirent)
{
	printf("%016llX\t%016llX\t%.*s\n",
		(unsigned long long) inum_decode(key->inum),
		(unsigned long long) dirent,
		(int)(key_len - sizeof(*key)),
		key->name);
}

static int show_dirs(void)
{
	DB_TXN *txn = NULL;
	DB *dirent = fsdb.dirent;
	DB_ENV *dbenv = fsdb.env;
	DBT pkey, pval;
	DBC *curs = NULL;
	int rc;
	uint64_t dirent_inum, db_de;

	printf("Parent          \tTarget inode    \tTarget name\n");

	/* open transaction */
	rc = dbenv->txn_begin(dbenv, NULL, &txn, 0);
	if (rc) {
		dbenv->err(dbenv, rc, "DB_ENV->txn_begin");
		goto out;
	}

	/* otherwise, loop through each dirent attached to ino->inum */
	rc = dirent->cursor(dirent, txn, &curs, 0);
	if (rc) {
		dirent->err(dirent, rc, "dirent->cursor");
		goto out_abort;
	}

	memset(&pkey, 0, sizeof(pkey));
	pkey.flags = DB_DBT_MALLOC;

	memset(&pval, 0, sizeof(pval));
	pval.data = &db_de;
	pval.ulen = sizeof(db_de);
	pval.flags = DB_DBT_USERMEM;

	while (1) {
		struct fsdb_de_key *rkey;

		rc = curs->get(curs, &pkey, &pval, DB_NEXT);
		if (rc) {
			if (rc != DB_NOTFOUND)
				dirent->err(dirent, rc, "readdir curs->get");
			break;
		}

		rkey = pkey.data;

		dirent_inum = inum_decode(db_de);

		readdir_iter(rkey, pkey.size, dirent_inum);

		free(rkey);
	}

	rc = curs->close(curs);
	if (rc) {
		dirent->err(dirent, rc, "dirent->cursor close");
		goto out_abort;
	}

	/* close transaction */
	rc = txn->commit(txn, 0);
	if (rc) {
		dbenv->err(dbenv, rc, "DB_ENV->txn_commit");
		goto out;
	}

out:
	return 0;

out_abort:
	if (txn->abort(txn))
		dbenv->err(dbenv, rc, "DB_ENV->txn_abort");
	goto out;
}

static int show_db(void)
{
	int rc;

	rc = show_inodes();
	if (rc)
		return 1;

	rc = show_dirs();
	if (rc)
		return 1;

	return 0;
}

static char *ddir;

static int mk_datadir(int v)
{
	if (!ddir) {
		ddir = malloc(strlen(opt_data_path) + 32);
		if (!ddir) {
			fprintf(stderr, PFX "out of memory\n");
			return 1;
		}
	}

	sprintf(ddir, "%s%02X", opt_data_path, v);

	if (mkdir(ddir, 0777) < 0) {
		perror(ddir);
		return 1;
	}

	return 0;
}

static int init_fs(void)
{
	int rc, i;
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

	ino->inum = inum_encode(INO_ROOT);
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
		fprintf(stderr, PFX "error storing root inode\n");
		return 1;
	}

	fprintf(stderr, PFX "root inode stored\n");

	for (i = 0; i <= 0xff; i++) {
		rc = mk_datadir(i);
		if (rc)
			return rc;
	}

	fprintf(stderr, PFX "data directories created\n");

	return 0;
}

static error_t parse_opt (int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'd':
		if (atoi(arg) >= 0 && atoi(arg) <= 2)
			debugging = atoi(arg);
		else {
			fprintf(stderr, PFX "invalid debug level %s (valid: 0-2)\n",
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

	case 'I':
		pmode = mode_init_fs;
		break;
	case 'S':
		pmode = mode_show;
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

	argp_program_version = PACKAGE_VERSION;
	argp_err_exit_status = EXIT_FAILURE;

	aprc = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (aprc) {
		fprintf(stderr, PFX "argp_parse failed: %s\n", strerror(aprc));
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
	case mode_init_fs:
		return init_fs();
	case mode_show:
		return show_db();

	default:
		break;
	}

	fsdb_close(&fsdb);

	return 1;
}

