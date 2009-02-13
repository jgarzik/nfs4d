#ifndef __NFSCOMMON_H__
#define __NFSCOMMON_H__

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

#endif /* __NFSCOMMON_H__ */
