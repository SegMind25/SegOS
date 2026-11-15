/*
 * Phase 5 conformance test: event descriptors (eventfd, timerfd,
 * signalfd, epoll, inotify). `cargo xtask test` runs it on Linux and on
 * SegOS; both must print exactly events.expected and exit with 0.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/inotify.h>
#include <sys/ioctl.h>
#include <sys/signalfd.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef SYS_epoll_pwait2
#define SYS_epoll_pwait2 441
#endif

static int failures;

#define CHECK(cond)                                                        \
	do {                                                               \
		errno = 0;                                                 \
		if (cond) {                                                \
			printf("ok   %s\n", #cond);                        \
		} else {                                                   \
			printf("FAIL %s (line %d, errno %d)\n", #cond,     \
			       __LINE__, errno);                           \
			failures++;                                        \
		}                                                          \
		fflush(stdout);                                            \
	} while (0)

static void section(const char *name)
{
	printf("# %s\n", name);
	fflush(stdout);
}

static void sleep_ms(int ms)
{
	struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };
	while (nanosleep(&ts, &ts) == -1 && errno == EINTR)
		;
}

static uint64_t rd64(int fd)
{
	uint64_t v = 0;
	if (read(fd, &v, 8) != 8)
		return (uint64_t)-1;
	return v;
}

static int wr64(int fd, uint64_t v)
{
	return write(fd, &v, 8) == 8;
}

static short revents(int fd, short events)
{
	struct pollfd p = { fd, events, 0 };
	if (poll(&p, 1, 0) < 0)
		return -1;
	return p.revents;
}

/* --- eventfd ------------------------------------------------------- */

static int efd_shared;

static void *late_writer(void *arg)
{
	sleep_ms(50);
	wr64(efd_shared, (uint64_t)(long)arg);
	return NULL;
}

static void eventfds(void)
{
	section("eventfd");
	int fd = eventfd(3, EFD_CLOEXEC);
	CHECK(fd >= 0);
	CHECK(fcntl(fd, F_GETFD) == FD_CLOEXEC);
	CHECK(revents(fd, POLLIN | POLLOUT) == (POLLIN | POLLOUT));
	CHECK(rd64(fd) == 3);
	CHECK(revents(fd, POLLIN | POLLOUT) == POLLOUT);
	CHECK(wr64(fd, 5) && wr64(fd, 2));
	CHECK(rd64(fd) == 7);
	char small[4];
	CHECK(read(fd, small, 4) == -1 && errno == EINVAL);
	uint64_t big = UINT64_MAX;
	CHECK(write(fd, &big, 8) == -1 && errno == EINVAL);
	struct stat st;
	CHECK(fstat(fd, &st) == 0);

	/* a blocking read waits for a writer */
	efd_shared = fd;
	pthread_t t;
	pthread_create(&t, NULL, late_writer, (void *)9L);
	CHECK(rd64(fd) == 9);
	pthread_join(t, NULL);
	close(fd);

	fd = eventfd(0, EFD_NONBLOCK);
	CHECK(fd >= 0 && (fcntl(fd, F_GETFL) & O_NONBLOCK));
	uint64_t v;
	CHECK(read(fd, &v, 8) == -1 && errno == EAGAIN);
	CHECK(wr64(fd, UINT64_MAX - 1));
	CHECK(write(fd, &(uint64_t){ 1 }, 8) == -1 && errno == EAGAIN);
	CHECK(revents(fd, POLLIN | POLLOUT) == POLLIN);
	CHECK(rd64(fd) == UINT64_MAX - 1);
	close(fd);

	section("eventfd semaphore");
	fd = eventfd(3, EFD_SEMAPHORE | EFD_NONBLOCK);
	CHECK(rd64(fd) == 1 && rd64(fd) == 1 && rd64(fd) == 1);
	CHECK(read(fd, &v, 8) == -1 && errno == EAGAIN);
	CHECK(wr64(fd, 2) && rd64(fd) == 1 && rd64(fd) == 1);
	close(fd);
	CHECK(eventfd(0, 0x1000) == -1 && errno == EINVAL);
}

/* --- timerfd -------------------------------------------------------- */

static void ms_spec(struct timespec *ts, long ms)
{
	ts->tv_sec = ms / 1000;
	ts->tv_nsec = (ms % 1000) * 1000000L;
}

static void timerfds(void)
{
	section("timerfd");
	int fd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC);
	CHECK(fd >= 0);
	struct itimerspec its, old;
	memset(&its, 0, sizeof its);
	CHECK(timerfd_gettime(fd, &old) == 0 && old.it_value.tv_sec == 0 &&
	      old.it_value.tv_nsec == 0);
	CHECK(revents(fd, POLLIN) == 0);

	/* one shot */
	ms_spec(&its.it_value, 30);
	CHECK(timerfd_settime(fd, 0, &its, NULL) == 0);
	CHECK(timerfd_gettime(fd, &old) == 0 && old.it_value.tv_sec == 0 &&
	      old.it_value.tv_nsec > 0 && old.it_value.tv_nsec <= 30000000L);
	CHECK(rd64(fd) == 1);
	CHECK(timerfd_gettime(fd, &old) == 0 && old.it_value.tv_nsec == 0);

	/* periodic */
	ms_spec(&its.it_value, 20);
	ms_spec(&its.it_interval, 20);
	CHECK(timerfd_settime(fd, 0, &its, NULL) == 0);
	CHECK(rd64(fd) >= 1);
	sleep_ms(110);
	CHECK(revents(fd, POLLIN) == POLLIN);
	uint64_t n = rd64(fd);
	CHECK(n >= 3 && n <= 7);
	CHECK(timerfd_gettime(fd, &old) == 0 && old.it_interval.tv_nsec == 20000000L);

	/* disarm returns the old setting */
	struct itimerspec zero;
	memset(&zero, 0, sizeof zero);
	CHECK(timerfd_settime(fd, 0, &zero, &old) == 0 &&
	      old.it_interval.tv_nsec == 20000000L);
	CHECK(timerfd_gettime(fd, &old) == 0 && old.it_value.tv_nsec == 0 &&
	      old.it_interval.tv_nsec == 0);
	CHECK(fcntl(fd, F_SETFL, O_NONBLOCK) == 0);
	uint64_t v;
	CHECK(read(fd, &v, 8) == -1 && errno == EAGAIN);
	close(fd);

	/* absolute time on the real-time clock */
	fd = timerfd_create(CLOCK_REALTIME, TFD_NONBLOCK);
	CHECK(fd >= 0);
	struct timespec now;
	clock_gettime(CLOCK_REALTIME, &now);
	memset(&its, 0, sizeof its);
	its.it_value = now;
	its.it_value.tv_nsec += 30000000L;
	if (its.it_value.tv_nsec >= 1000000000L) {
		its.it_value.tv_sec++;
		its.it_value.tv_nsec -= 1000000000L;
	}
	CHECK(timerfd_settime(fd, TFD_TIMER_ABSTIME, &its, NULL) == 0);
	CHECK(read(fd, &v, 8) == -1 && errno == EAGAIN);
	struct pollfd p = { fd, POLLIN, 0 };
	CHECK(poll(&p, 1, 2000) == 1 && p.revents == POLLIN);
	CHECK(rd64(fd) == 1);
	/* a time in the past expires at once */
	its.it_value.tv_sec -= 10;
	CHECK(timerfd_settime(fd, TFD_TIMER_ABSTIME, &its, NULL) == 0);
	/* (Linux expires it from a timer interrupt: wait for that.) */
	CHECK(poll(&p, 1, 2000) == 1 && p.revents == POLLIN);
	CHECK(rd64(fd) == 1);
	close(fd);

	CHECK(timerfd_create(12345, 0) == -1 && errno == EINVAL);
	CHECK(timerfd_settime(0, 0, &its, NULL) == -1 && errno == EINVAL);
}

/* --- signalfd ------------------------------------------------------- */

static void signalfds(void)
{
	section("signalfd");
	sigset_t set, old;
	sigemptyset(&set);
	sigaddset(&set, SIGUSR1);
	sigaddset(&set, SIGCHLD);
	sigprocmask(SIG_BLOCK, &set, &old);
	int fd = signalfd(-1, &set, SFD_NONBLOCK | SFD_CLOEXEC);
	CHECK(fd >= 0);
	struct signalfd_siginfo si;
	CHECK(read(fd, &si, sizeof si) == -1 && errno == EAGAIN);
	CHECK(revents(fd, POLLIN) == 0);

	CHECK(kill(getpid(), SIGUSR1) == 0);
	CHECK(revents(fd, POLLIN) == POLLIN);
	memset(&si, 0, sizeof si);
	CHECK(read(fd, &si, sizeof si) == sizeof si);
	CHECK(si.ssi_signo == SIGUSR1 && si.ssi_code == SI_USER &&
	      si.ssi_pid == (uint32_t)getpid());
	CHECK(read(fd, &si, sizeof si) == -1 && errno == EAGAIN);

	CHECK(syscall(SYS_tgkill, getpid(), syscall(SYS_gettid), SIGUSR1) == 0);
	CHECK(read(fd, &si, sizeof si) == sizeof si);
	CHECK(si.ssi_signo == SIGUSR1 && si.ssi_code == SI_TKILL);

	char small[16];
	CHECK(read(fd, small, sizeof small) == -1 && errno == EINVAL);

	/* SIGCHLD with the child's status */
	pid_t p = fork();
	if (p == 0)
		_exit(7);
	struct pollfd pf = { fd, POLLIN, 0 };
	CHECK(poll(&pf, 1, 5000) == 1);
	CHECK(read(fd, &si, sizeof si) == sizeof si);
	CHECK(si.ssi_signo == SIGCHLD && si.ssi_code == CLD_EXITED &&
	      si.ssi_status == 7 && si.ssi_pid == (uint32_t)p);
	waitpid(p, NULL, 0);

	/* changing the mask of an existing signalfd */
	sigset_t only_usr2;
	sigemptyset(&only_usr2);
	sigaddset(&only_usr2, SIGUSR2);
	CHECK(signalfd(fd, &only_usr2, 0) == fd);
	kill(getpid(), SIGUSR1);
	CHECK(read(fd, &si, sizeof si) == -1 && errno == EAGAIN);
	CHECK(signalfd(fd, &set, 0) == fd);
	CHECK(read(fd, &si, sizeof si) == sizeof si && si.ssi_signo == SIGUSR1);
	int notsfd = eventfd(0, 0);
	CHECK(signalfd(notsfd, &set, 0) == -1 && errno == EINVAL);
	close(notsfd);
	close(fd);
	sigprocmask(SIG_SETMASK, &old, NULL);
}

/* --- epoll ---------------------------------------------------------- */

static int add(int ep, int fd, uint32_t events, uint64_t data)
{
	struct epoll_event e = { .events = events, .data.u64 = data };
	return epoll_ctl(ep, EPOLL_CTL_ADD, fd, &e);
}

static int mod(int ep, int fd, uint32_t events, uint64_t data)
{
	struct epoll_event e = { .events = events, .data.u64 = data };
	return epoll_ctl(ep, EPOLL_CTL_MOD, fd, &e);
}

static struct epoll_event evs[8];

/* epoll_wait, with the events sorted by data. */
static int wait_sorted(int ep, int timeout)
{
	int n = epoll_wait(ep, evs, 8, timeout);
	for (int i = 1; i < n; i++)
		for (int j = i; j > 0 && evs[j - 1].data.u64 > evs[j].data.u64;
		     j--) {
			struct epoll_event t = evs[j];
			evs[j] = evs[j - 1];
			evs[j - 1] = t;
		}
	return n;
}

static void *poke(void *arg)
{
	sleep_ms(50);
	wr64((int)(long)arg, 1);
	return NULL;
}

static void epolls(void)
{
	section("epoll");
	int ep = epoll_create1(EPOLL_CLOEXEC);
	CHECK(ep >= 0);
	CHECK(epoll_create1(0x1234) == -1 && errno == EINVAL);
	CHECK(epoll_create(0) == -1 && errno == EINVAL);
	int pfd[2];
	pipe(pfd);
	int efd = eventfd(0, EFD_NONBLOCK);
	int tfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
	CHECK(add(ep, pfd[0], EPOLLIN, 1) == 0);
	CHECK(add(ep, efd, EPOLLIN, 2) == 0);
	CHECK(add(ep, tfd, EPOLLIN, 3) == 0);
	CHECK(add(ep, efd, EPOLLIN, 2) == -1 && errno == EEXIST);
	CHECK(add(ep, ep, EPOLLIN, 9) == -1 && errno == EINVAL);
	int reg = open("/proc/self/exe", O_RDONLY);
	CHECK(add(ep, reg, EPOLLIN, 9) == -1 && errno == EPERM);
	close(reg);
	CHECK(epoll_ctl(ep, EPOLL_CTL_DEL, pfd[1], NULL) == -1 && errno == ENOENT);
	CHECK(mod(ep, pfd[1], EPOLLOUT, 9) == -1 && errno == ENOENT);
	CHECK(epoll_wait(ep, evs, 8, 0) == 0);
	CHECK(epoll_wait(ep, evs, 0, 0) == -1 && errno == EINVAL);

	/* level-triggered: reported until drained */
	write(pfd[1], "ab", 2);
	CHECK(wait_sorted(ep, 0) == 1 && evs[0].data.u64 == 1 &&
	      evs[0].events == EPOLLIN);
	CHECK(wait_sorted(ep, 0) == 1);
	wr64(efd, 4);
	CHECK(wait_sorted(ep, 0) == 2 && evs[0].data.u64 == 1 &&
	      evs[1].data.u64 == 2);
	char buf[8];
	read(pfd[0], buf, sizeof buf);
	rd64(efd);
	CHECK(wait_sorted(ep, 0) == 0);

	/* a timer wakes a blocked epoll_wait */
	struct itimerspec its;
	memset(&its, 0, sizeof its);
	its.it_value.tv_nsec = 30000000L;
	timerfd_settime(tfd, 0, &its, NULL);
	CHECK(wait_sorted(ep, 5000) == 1 && evs[0].data.u64 == 3);
	CHECK(rd64(tfd) == 1);

	/* a write from another thread wakes it too */
	pthread_t t;
	pthread_create(&t, NULL, poke, (void *)(long)efd);
	CHECK(wait_sorted(ep, 5000) == 1 && evs[0].data.u64 == 2);
	pthread_join(t, NULL);
	rd64(efd);

	/* timeouts */
	CHECK(epoll_wait(ep, evs, 8, 30) == 0);
	struct timespec ts = { 0, 20000000L };
	CHECK(syscall(SYS_epoll_pwait2, ep, evs, 8, &ts, NULL, 8) == 0);
	sigset_t mask;
	sigemptyset(&mask);
	CHECK(epoll_pwait(ep, evs, 8, 10, &mask) == 0);

	section("epoll edge-triggered and one-shot");
	CHECK(mod(ep, pfd[0], EPOLLIN | EPOLLET, 1) == 0);
	write(pfd[1], "x", 1);
	CHECK(wait_sorted(ep, 0) == 1 && evs[0].data.u64 == 1);
	CHECK(wait_sorted(ep, 0) == 0);
	read(pfd[0], buf, sizeof buf);
	write(pfd[1], "y", 1);
	CHECK(wait_sorted(ep, 0) == 1 && evs[0].data.u64 == 1);
	read(pfd[0], buf, sizeof buf);

	CHECK(mod(ep, efd, EPOLLIN | EPOLLONESHOT, 22) == 0);
	wr64(efd, 1);
	CHECK(wait_sorted(ep, 0) == 1 && evs[0].data.u64 == 22);
	CHECK(wait_sorted(ep, 0) == 0);
	CHECK(mod(ep, efd, EPOLLIN | EPOLLONESHOT, 23) == 0);
	CHECK(wait_sorted(ep, 0) == 1 && evs[0].data.u64 == 23);
	CHECK(wait_sorted(ep, 0) == 0);
	rd64(efd);

	section("epoll nesting, hang-up and close");
	int outer = epoll_create1(0);
	CHECK(add(outer, ep, EPOLLIN, 100) == 0);
	CHECK(add(ep, outer, EPOLLIN, 101) == -1 && errno == ELOOP);
	CHECK(epoll_wait(outer, evs, 8, 0) == 0);
	CHECK(revents(ep, POLLIN) == 0);
	CHECK(mod(ep, efd, EPOLLIN, 2) == 0);
	wr64(efd, 1);
	CHECK(revents(ep, POLLIN) == POLLIN);
	CHECK(epoll_wait(outer, evs, 8, 0) == 1 && evs[0].data.u64 == 100);
	rd64(efd);
	CHECK(epoll_wait(outer, evs, 8, 0) == 0);

	CHECK(epoll_ctl(ep, EPOLL_CTL_DEL, efd, NULL) == 0);
	wr64(efd, 1);
	CHECK(wait_sorted(ep, 0) == 0);

	CHECK(mod(ep, pfd[0], EPOLLIN, 1) == 0);
	close(pfd[1]);
	CHECK(wait_sorted(ep, 0) == 1 && evs[0].events == EPOLLHUP);
	/* closing the last descriptor of a file removes it */
	close(pfd[0]);
	CHECK(wait_sorted(ep, 0) == 0);

	/* EPOLLOUT on a pipe's write end */
	pipe(pfd);
	CHECK(add(ep, pfd[1], EPOLLOUT, 7) == 0);
	CHECK(wait_sorted(ep, 0) == 1 && evs[0].events == EPOLLOUT &&
	      evs[0].data.u64 == 7);
	close(pfd[0]);
	CHECK(wait_sorted(ep, 0) == 1 &&
	      evs[0].events == (EPOLLOUT | EPOLLERR));
	close(pfd[1]);
	close(outer);
	close(ep);
	close(efd);
	close(tfd);
}

/* --- inotify -------------------------------------------------------- */

static int inotify_events(int fd, char *out, size_t size)
{
	char buf[4096] __attribute__((aligned(8)));
	ssize_t n = read(fd, buf, sizeof buf);
	size_t used = 0;
	static uint32_t cookie;
	out[0] = 0;
	for (ssize_t at = 0; at < n;) {
		struct inotify_event *e = (struct inotify_event *)(buf + at);
		const char *same = "";
		if (e->cookie) {
			same = cookie == e->cookie ? "=" : "*";
			cookie = e->cookie;
		}
		used += snprintf(out + used, size - used, "%s%d:%x%s:%s",
				 used ? " " : "", e->wd, e->mask, same,
				 e->len ? e->name : "");
		at += sizeof *e + e->len;
	}
	return n;
}

static void inotify(void)
{
	section("inotify");
	int fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
	CHECK(fd >= 0);
	CHECK(inotify_add_watch(fd, "/proc", IN_CREATE) >= 1);
	CHECK(inotify_add_watch(fd, "/no/such/dir", IN_CREATE) == -1 &&
	      errno == ENOENT);
	char buf[256];
	CHECK(read(fd, buf, sizeof buf) == -1 && errno == EAGAIN);
	CHECK(revents(fd, POLLIN) == 0);

	char dir[] = "/tmp/inotifyXXXXXX", path[64], path2[64];
	CHECK(mkdtemp(dir) != NULL);
	int wd = inotify_add_watch(fd, dir, IN_CREATE | IN_DELETE | IN_MODIFY |
					    IN_MOVED_FROM | IN_MOVED_TO |
					    IN_CLOSE_WRITE | IN_ATTRIB);
	CHECK(wd >= 2);
	CHECK(inotify_add_watch(fd, dir, IN_DELETE | IN_MASK_CREATE) == -1 &&
	      errno == EEXIST);
	CHECK(inotify_add_watch(fd, dir, IN_ACCESS | IN_MASK_ADD) == wd);
	snprintf(path, sizeof path, "%s/a", dir);
	int f = open(path, O_CREAT | O_WRONLY, 0644);
	CHECK(f >= 0 && write(f, "x", 1) == 1 && close(f) == 0);
	snprintf(path2, sizeof path2, "%s/b", dir);
	CHECK(rename(path, path2) == 0 && chmod(path2, 0600) == 0);
	snprintf(path, sizeof path, "%s/sub", dir);
	CHECK(mkdir(path, 0755) == 0 && rmdir(path) == 0);
	int n = 0;
	CHECK(ioctl(fd, FIONREAD, &n) == 0 && n > 0);
	CHECK(revents(fd, POLLIN) == POLLIN);
	char events[1024];
	CHECK(inotify_events(fd, events, sizeof events) == n);
	printf("     %s\n", events);

	/* A watch on the file itself: IN_DELETE_SELF, then IN_IGNORED. */
	CHECK(inotify_add_watch(fd, path2, IN_MODIFY | IN_ONLYDIR) == -1 &&
	      errno == ENOTDIR);
	int wd2 = inotify_add_watch(fd, path2, IN_MODIFY | IN_DELETE_SELF);
	CHECK(wd2 == wd + 1);
	f = open(path2, O_WRONLY);
	CHECK(f >= 0 && write(f, "y", 1) == 1 && close(f) == 0);
	CHECK(unlink(path2) == 0);
	CHECK(inotify_events(fd, events, sizeof events) > 0);
	printf("     %s\n", events);
	CHECK(inotify_rm_watch(fd, wd2) == -1 && errno == EINVAL);
	CHECK(inotify_rm_watch(fd, wd) == 0);
	CHECK(inotify_events(fd, events, sizeof events) > 0);
	printf("     %s\n", events);
	CHECK(rmdir(dir) == 0);
	close(fd);
}

int main(void)
{
	setvbuf(stdout, NULL, _IOLBF, 0);
	eventfds();
	timerfds();
	signalfds();
	epolls();
	inotify();
	printf("%s\n", failures ? "FAILED" : "PASSED");
	return failures != 0;
}
