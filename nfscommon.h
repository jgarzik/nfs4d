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

typedef void (*timer_cb_t)(struct timer *);

struct timer {
	time_t			timeout;
	bool			fired;
	timer_cb_t		cb;
	void			*cb_data;
};

/* util.c */
extern const char *name_nfs_ftype4[];
extern struct timeval current_time;
extern int write_pid_file(const char *pid_fn);
extern void syslogerr(const char *prefix);
extern int fsetflags(const char *prefix, int fd, int or_flags);
extern void timer_add(struct timer *timer);
extern int timer_next(void);
extern void timers_run(void);
extern void timers_init(void);
extern void timer_init(struct timer *timer, timer_cb_t cb, void *cb_data);
extern void timer_renew(struct timer *timer, time_t timeout);
extern void timer_del(struct timer *timer);
extern bool is_dir(const char *arg, char **dirname);
extern void nrand32(void *mem, unsigned int dwords);
extern void init_rngs(void);
extern char *copy_binstr(const char *s_in, size_t s_len);

#endif /* __NFSCOMMON_H__ */
