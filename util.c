
#define _GNU_SOURCE
#include "nfs4d-config.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <syslog.h>
#include <time.h>
#include "server.h"

struct timeval current_time = { 0, 0 };
static GQueue *timers_q;
static struct drand48_data rng;

int write_pid_file(const char *pid_fn)
{
	char str[32], *s;
	size_t bytes;

	/* build file data */
	sprintf(str, "%u\n", getpid());
	s = str;
	bytes = strlen(s);

	/* exclusive open */
	int fd = open(pid_fn, O_WRONLY | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		syslogerr(pid_fn);
		return -errno;
	}

	/* write file data */
	while (bytes > 0) {
		ssize_t rc = write(fd, s, bytes);
		if (rc < 0) {
			syslogerr("pid data write failed");
			goto err_out;
		}

		bytes -= rc;
		s += rc;
	}

	/* make sure file data is written to disk */
	if ((fsync(fd) < 0) || (close(fd) < 0)) {
		syslogerr("pid file sync/close failed");
		goto err_out;
	}

	return 0;

err_out:
	close(fd);
	unlink(pid_fn);
	return -errno;
}

void syslogerr(const char *prefix)
{
	syslog(LOG_ERR, "%s: %s", prefix, strerror(errno));
}

void syslogerr2(const char *pfx1, const char *pfx2)
{
	syslog(LOG_ERR, "%s(%s): %s", pfx1, pfx2, strerror(errno));
}

int fsetflags(const char *prefix, int fd, int or_flags)
{
	int flags, old_flags, rc;

	/* get current flags */
	old_flags = fcntl(fd, F_GETFL);
	if (old_flags < 0) {
		syslog(LOG_ERR, "%s F_GETFL: %s", prefix, strerror(errno));
		return -errno;
	}

	/* add or_flags */
	rc = 0;
	flags = old_flags | or_flags;

	/* set new flags */
	if (flags != old_flags)
		if (fcntl(fd, F_SETFL, flags) < 0) {
			syslog(LOG_ERR, "%s F_SETFL: %s", prefix, strerror(errno));
			rc = -errno;
		}

	return rc;
}

static gint timer_cmp(gconstpointer _a, gconstpointer _b, gpointer user_data)
{
	const struct timer *a = _a;
	const struct timer *b = _b;
	int64_t at = a->timeout;
	int64_t bt = b->timeout;

	return (at - bt);
}

void timer_init(struct timer *timer, timer_cb_t cb, void *cb_data)
{
	timer->timeout = 0;
	timer->fired = false;
	timer->cb = cb;
	timer->cb_data = cb_data;
}

void timer_add(struct timer *timer)
{
	timer->fired = false;
	g_queue_insert_sorted(timers_q, timer, timer_cmp, NULL);
}

void timer_del(struct timer *timer)
{
	g_queue_remove(timers_q, timer);
}

void timer_renew(struct timer *timer, time_t timeout)
{
	timer_del(timer);

	timer->timeout = current_time.tv_sec + timeout;
	timer_add(timer);
}

int timer_next(void)
{
	struct timer *timer = g_queue_peek_head(timers_q);
	if (!timer)
		return -1;

	if (current_time.tv_sec >= timer->timeout)
		return 0;

	return (timer->timeout - current_time.tv_sec) * 1000;
}

void timers_run(void)
{
	while (1) {
		struct timer *timer;

		timer = g_queue_peek_head(timers_q);
		if (!timer)
			break;
		if (current_time.tv_sec < timer->timeout)
			break;

		g_queue_pop_head(timers_q);

		timer->fired = true;
		timer->cb(timer);
	}
}

void timers_init(void)
{
	timers_q = g_queue_new();
}

bool is_dir(const char *arg, char **dirname)
{
	struct stat st;
	char *s = NULL;

	*dirname = NULL;

	if (stat(arg, &st) < 0) {
		perror(arg);
		return false;
	}

	if (!S_ISDIR(st.st_mode)) {
		fprintf(stderr, "%s: not a directory\n", arg);
		return false;
	}

	if (arg[strlen(arg) - 1] == '/') {
		s = strdup(arg);
		if (s) {
			*dirname = s;
			return true;
		} else
			return false;
	}

	if (asprintf(&s, "%s/", arg) < 0) {
		fprintf(stderr, "asprintf error in is_dir()\n");
		return false;
	}

	*dirname = s;
	return true;
}

void nrand32(void *mem, unsigned int dwords)
{
	uint32_t *v = mem;
	long l[4] = { 0, };
	int i;

	for (i = 0; i < dwords; i++) {
		lrand48_r(&rng, l);

		v[i] = l[0];
	}
}

/* seed our RNGs with high quality data from /dev/random */
void init_rngs(void)
{
	unsigned long v;
	int fd;
	ssize_t bytes;

	fd = open("/dev/random", O_RDONLY);
	if (fd < 0) {
		syslogerr("/dev/random");
		goto srand_time;
	}

	bytes = read(fd, &v, sizeof(v));
	if (bytes < 0)
		syslogerr("/dev/random read");

	close(fd);

	if (bytes < sizeof(v))
		goto srand_time;

	srand48_r(v, &rng);
	srand(v);
	return;

srand_time:
	srand48_r(getpid() ^ time(NULL), &rng);
	srand(getpid() ^ time(NULL));
}

