#ifndef __NFSCOMMON_H__
#define __NFSCOMMON_H__

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


struct timer;

enum various_inode_numbers {
	INO_ROOT		= 10,
	INO_FIRST		= INO_ROOT,
	INO_RESERVED_LAST	= 99,
};

/* util.c */
extern bool use_syslog;
extern const char *name_nfs_ftype4[];
extern struct timeval current_time;
extern void applog(int prio, const char *fmt, ...);
extern int write_pid_file(const char *pid_fn);
extern void syslogerr(const char *prefix);
extern int fsetflags(const char *prefix, int fd, int or_flags);
extern bool is_dir(const char *arg, char **dirname);
extern void nrand32(void *mem, unsigned int dwords);
extern void init_rngs(void);
extern char *copy_binstr(const char *s_in, size_t s_len);
extern void *memdup(void *p, size_t sz);
extern char *hexstr(char *str, const char *buf, size_t sz);

#ifndef HAVE_FDATASYNC
extern int fdatasync(int fd);
#endif

#ifndef HAVE_LSEEK64
extern off_t lseek64(int fd, off_t offset, int whence);
#endif

#endif /* __NFSCOMMON_H__ */
