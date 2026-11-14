/*
 * Phase 5 conformance test: threads and futexes. `cargo xtask test` runs
 * it on Linux and on SegOS; both must print exactly threads.expected and
 * exit with 0. No pids, tids or times in the output.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <dirent.h>
#include <time.h>
#include <unistd.h>

/* <linux/futex.h> is not part of musl's headers. */
#define FUTEX_WAIT 0
#define FUTEX_WAKE 1
#define FUTEX_REQUEUE 3
#define FUTEX_CMP_REQUEUE 4
#define FUTEX_WAKE_OP 5
#define FUTEX_WAIT_BITSET 9
#define FUTEX_WAKE_BITSET 10
#define FUTEX_PRIVATE_FLAG 128
#define FUTEX_CLOCK_REALTIME 256
#define FUTEX_WAIT_PRIVATE (FUTEX_WAIT | FUTEX_PRIVATE_FLAG)
#define FUTEX_WAKE_PRIVATE (FUTEX_WAKE | FUTEX_PRIVATE_FLAG)
#define FUTEX_REQUEUE_PRIVATE (FUTEX_REQUEUE | FUTEX_PRIVATE_FLAG)
#define FUTEX_CMP_REQUEUE_PRIVATE (FUTEX_CMP_REQUEUE | FUTEX_PRIVATE_FLAG)
#define FUTEX_WAKE_OP_PRIVATE (FUTEX_WAKE_OP | FUTEX_PRIVATE_FLAG)
#define FUTEX_WAIT_BITSET_PRIVATE (FUTEX_WAIT_BITSET | FUTEX_PRIVATE_FLAG)
#define FUTEX_WAKE_BITSET_PRIVATE (FUTEX_WAKE_BITSET | FUTEX_PRIVATE_FLAG)
#define FUTEX_OP_SET 0
#define FUTEX_OP_ADD 1
#define FUTEX_OP_CMP_EQ 0
#define FUTEX_OP_CMP_GT 4
#define FUTEX_OP(op, oparg, cmp, cmparg)                                   \
	((((op) & 0xf) << 28) | (((cmp) & 0xf) << 24) |                    \
	 (((oparg) & 0xfff) << 12) | ((cmparg) & 0xfff))

static int failures;
static char *self;

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

static pid_t gettid_(void)
{
	return (pid_t)syscall(SYS_gettid);
}

static long futex(int *uaddr, int op, int val, const void *timeout,
		  int *uaddr2, int val3)
{
	return syscall(SYS_futex, uaddr, op, val, timeout, uaddr2, val3);
}

static void sleep_ms(int ms)
{
	struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };
	while (nanosleep(&ts, &ts) == -1 && errno == EINTR)
		;
}

static int status_of(pid_t p)
{
	int st = -1;
	while (waitpid(p, &st, 0) == -1 && errno == EINTR)
		;
	return st;
}

/* --- create, join, identity -------------------------------------- */

static pid_t main_pid;

static void *identity(void *arg)
{
	long ok = getpid() == main_pid && gettid_() != getpid();
	return (void *)(ok + (long)arg);
}

static void create_join(void)
{
	section("create and join");
	main_pid = getpid();
	CHECK(gettid_() == getpid());
	pthread_t t;
	CHECK(pthread_create(&t, NULL, identity, (void *)41) == 0);
	void *ret = NULL;
	CHECK(pthread_join(t, &ret) == 0);
	CHECK(ret == (void *)42);
	pthread_t ts[16];
	int ok = 1;
	for (int i = 0; i < 16; i++)
		ok &= pthread_create(&ts[i], NULL, identity, (void *)(long)i) == 0;
	long sum = 0;
	for (int i = 0; i < 16; i++) {
		pthread_join(ts[i], &ret);
		sum += (long)ret;
	}
	CHECK(ok);
	CHECK(sum == 16 + 120);
	/* wait4 never reaps threads */
	CHECK(waitpid(-1, NULL, WNOHANG) == -1 && errno == ECHILD);
}

/* --- mutexes and condition variables across 8 threads ------------- */

#define NT 8
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
static long counter;
static int queue[64], qhead, qtail;
static long consumed;

static void *adder(void *arg)
{
	(void)arg;
	for (int i = 0; i < 20000; i++) {
		pthread_mutex_lock(&lock);
		counter++;
		pthread_mutex_unlock(&lock);
	}
	return NULL;
}

static void *consumer(void *arg)
{
	(void)arg;
	long sum = 0;
	for (;;) {
		pthread_mutex_lock(&lock);
		while (qhead == qtail)
			pthread_cond_wait(&cond, &lock);
		int v = queue[qhead++ % 64];
		pthread_cond_broadcast(&cond);
		pthread_mutex_unlock(&lock);
		if (v < 0)
			break;
		sum += v;
	}
	pthread_mutex_lock(&lock);
	consumed += sum;
	pthread_mutex_unlock(&lock);
	return NULL;
}

static void contention(void)
{
	section("mutex and condvar contention");
	pthread_t t[NT];
	for (int i = 0; i < NT; i++)
		pthread_create(&t[i], NULL, adder, NULL);
	for (int i = 0; i < NT; i++)
		pthread_join(t[i], NULL);
	CHECK(counter == NT * 20000);

	for (int i = 0; i < NT; i++)
		pthread_create(&t[i], NULL, consumer, NULL);
	long want = 0;
	for (int i = 1; i <= 5000 + NT; i++) {
		int v = i <= 5000 ? i : -1;
		if (v > 0)
			want += v;
		pthread_mutex_lock(&lock);
		while (qtail - qhead == 64)
			pthread_cond_wait(&cond, &lock);
		queue[qtail++ % 64] = v;
		pthread_cond_broadcast(&cond);
		pthread_mutex_unlock(&lock);
	}
	for (int i = 0; i < NT; i++)
		pthread_join(t[i], NULL);
	CHECK(consumed == want);
}

/* --- broadcast wakes every waiter ------------------------------- */

static int ready_count, go;

static void *bcast_waiter(void *arg)
{
	(void)arg;
	pthread_mutex_lock(&lock);
	ready_count++;
	pthread_cond_broadcast(&cond);
	while (!go)
		pthread_cond_wait(&cond, &lock);
	ready_count--;
	pthread_mutex_unlock(&lock);
	return NULL;
}

static void broadcast(void)
{
	section("condvar broadcast");
	pthread_t t[NT];
	ready_count = 0;
	go = 0;
	for (int i = 0; i < NT; i++)
		pthread_create(&t[i], NULL, bcast_waiter, NULL);
	pthread_mutex_lock(&lock);
	while (ready_count < NT)
		pthread_cond_wait(&cond, &lock);
	go = 1;
	pthread_cond_broadcast(&cond);
	pthread_mutex_unlock(&lock);
	for (int i = 0; i < NT; i++)
		pthread_join(t[i], NULL);
	CHECK(ready_count == 0);
}

/* --- thread-local storage and pthread_exit ------------------------ */

static __thread int tls_value = 7;
static __thread char tls_buf[64];

__attribute__((noinline)) static void exit_inner(void)
{
	pthread_exit((void *)(long)(tls_value + 1000));
}

__attribute__((noinline)) static void exit_from_deep(void)
{
	exit_inner();
}

static void *tls_thread(void *arg)
{
	long n = (long)arg;
	int ok = tls_value == 7 && tls_buf[0] == 0;
	tls_value = (int)n;
	snprintf(tls_buf, sizeof tls_buf, "thread %ld", n);
	sleep_ms(10);
	char want[64];
	snprintf(want, sizeof want, "thread %ld", n);
	ok &= tls_value == n && strcmp(tls_buf, want) == 0;
	if (!ok)
		return (void *)-1L;
	exit_from_deep();
	return NULL;
}

static void tls(void)
{
	section("thread-local storage and pthread_exit");
	pthread_t t[NT];
	tls_value = 99;
	for (long i = 0; i < NT; i++)
		pthread_create(&t[i], NULL, tls_thread, (void *)i);
	long sum = 0;
	for (int i = 0; i < NT; i++) {
		void *r;
		pthread_join(t[i], &r);
		sum += (long)r;
	}
	CHECK(sum == NT * 1000 + 28);
	CHECK(tls_value == 99);
}

/* --- futex operations ---------------------------------------------- */

static int fword, fword2, woke_count;

struct fwait {
	int *addr;
	int val;
	unsigned bitset;
	long ret;
	int err;
};

static void *futex_waiter(void *arg)
{
	struct fwait *w = arg;
	__atomic_fetch_add(&ready_count, 1, __ATOMIC_SEQ_CST);
	if (w->bitset)
		w->ret = futex(w->addr, FUTEX_WAIT_BITSET_PRIVATE, w->val, NULL,
			       NULL, (int)w->bitset);
	else
		w->ret = futex(w->addr, FUTEX_WAIT_PRIVATE, w->val, NULL, NULL,
			       0);
	w->err = w->ret ? errno : 0;
	__atomic_fetch_add(&woke_count, 1, __ATOMIC_SEQ_CST);
	return NULL;
}

/* Starts n waiters on addr and gives them time to sleep. */
static void start_waiters(pthread_t *t, struct fwait *w, int n, int *addr,
			  const unsigned *bitsets)
{
	ready_count = 0;
	woke_count = 0;
	for (int i = 0; i < n; i++) {
		w[i] = (struct fwait){ addr, *addr, bitsets ? bitsets[i] : 0, -1,
				       0 };
		pthread_create(&t[i], NULL, futex_waiter, &w[i]);
	}
	while (__atomic_load_n(&ready_count, __ATOMIC_SEQ_CST) < n)
		sleep_ms(1);
	sleep_ms(100);
}

static void futexes(void)
{
	section("futex wait and wake");
	pthread_t t[8];
	struct fwait w[8];
	struct timespec rel = { 0, 50 * 1000000L };

	fword = 1;
	CHECK(futex(&fword, FUTEX_WAIT_PRIVATE, 2, NULL, NULL, 0) == -1 &&
	      errno == EAGAIN);
	CHECK(futex(&fword, FUTEX_WAIT_PRIVATE, 1, &rel, NULL, 0) == -1 &&
	      errno == ETIMEDOUT);
	CHECK(futex(&fword, FUTEX_WAKE_PRIVATE, 5, NULL, NULL, 0) == 0);
	CHECK(futex((int *)((char *)&fword + 1), FUTEX_WAKE, 1, NULL, NULL,
		    0) == -1 &&
	      errno == EINVAL);

	start_waiters(t, w, 4, &fword, NULL);
	CHECK(futex(&fword, FUTEX_WAKE_PRIVATE, 2, NULL, NULL, 0) == 2);
	sleep_ms(50);
	CHECK(__atomic_load_n(&woke_count, __ATOMIC_SEQ_CST) == 2);
	CHECK(futex(&fword, FUTEX_WAKE_PRIVATE, 10, NULL, NULL, 0) == 2);
	for (int i = 0; i < 4; i++)
		pthread_join(t[i], NULL);
	CHECK(w[0].ret == 0 && w[1].ret == 0 && w[2].ret == 0 && w[3].ret == 0);

	section("futex bitsets");
	unsigned bits[3] = { 1, 2, 3 };
	start_waiters(t, w, 3, &fword, bits);
	CHECK(futex(&fword, FUTEX_WAKE_BITSET_PRIVATE, 10, NULL, NULL, 4) == 0);
	CHECK(futex(&fword, FUTEX_WAKE_BITSET_PRIVATE, 10, NULL, NULL, 2) == 2);
	sleep_ms(50);
	CHECK(__atomic_load_n(&woke_count, __ATOMIC_SEQ_CST) == 2);
	CHECK(futex(&fword, FUTEX_WAKE_BITSET_PRIVATE, 10, NULL, NULL, 0) ==
		      -1 &&
	      errno == EINVAL);
	CHECK(futex(&fword, FUTEX_WAKE_PRIVATE, 10, NULL, NULL, 0) == 1);
	for (int i = 0; i < 3; i++)
		pthread_join(t[i], NULL);

	section("futex timeouts");
	struct timespec now, abs;
	clock_gettime(CLOCK_MONOTONIC, &now);
	abs = now;
	abs.tv_nsec += 30 * 1000000L;
	if (abs.tv_nsec >= 1000000000L) {
		abs.tv_sec++;
		abs.tv_nsec -= 1000000000L;
	}
	CHECK(futex(&fword, FUTEX_WAIT_BITSET_PRIVATE, 1, &abs, NULL, -1) ==
		      -1 &&
	      errno == ETIMEDOUT);
	struct timespec after;
	clock_gettime(CLOCK_MONOTONIC, &after);
	CHECK(after.tv_sec > abs.tv_sec ||
	      (after.tv_sec == abs.tv_sec && after.tv_nsec >= abs.tv_nsec));
	clock_gettime(CLOCK_REALTIME, &abs);
	abs.tv_nsec += 30 * 1000000L;
	if (abs.tv_nsec >= 1000000000L) {
		abs.tv_sec++;
		abs.tv_nsec -= 1000000000L;
	}
	CHECK(futex(&fword, FUTEX_WAIT_BITSET_PRIVATE | FUTEX_CLOCK_REALTIME,
		    1, &abs, NULL, -1) == -1 &&
	      errno == ETIMEDOUT);
	struct timespec bad = { 0, 2000000000L };
	CHECK(futex(&fword, FUTEX_WAIT_PRIVATE, 1, &bad, NULL, 0) == -1 &&
	      errno == EINVAL);

	section("futex requeue");
	fword2 = 0;
	start_waiters(t, w, 4, &fword, NULL);
	CHECK(futex(&fword, FUTEX_CMP_REQUEUE_PRIVATE, 1, (void *)10L, &fword2,
		    5) == -1 &&
	      errno == EAGAIN);
	CHECK(futex(&fword, FUTEX_CMP_REQUEUE_PRIVATE, 1, (void *)10L, &fword2,
		    1) == 4);
	sleep_ms(50);
	CHECK(__atomic_load_n(&woke_count, __ATOMIC_SEQ_CST) == 1);
	CHECK(futex(&fword, FUTEX_WAKE_PRIVATE, 10, NULL, NULL, 0) == 0);
	CHECK(futex(&fword2, FUTEX_WAKE_PRIVATE, 2, NULL, NULL, 0) == 2);
	CHECK(futex(&fword2, FUTEX_WAKE_PRIVATE, 10, NULL, NULL, 0) == 1);
	for (int i = 0; i < 4; i++)
		pthread_join(t[i], NULL);
	start_waiters(t, w, 2, &fword, NULL);
	CHECK(futex(&fword, FUTEX_REQUEUE_PRIVATE, 0, (void *)1L, &fword2, 0) ==
	      1);
	CHECK(futex(&fword, FUTEX_WAKE_PRIVATE, 10, NULL, NULL, 0) == 1);
	CHECK(futex(&fword2, FUTEX_WAKE_PRIVATE, 10, NULL, NULL, 0) == 1);
	for (int i = 0; i < 2; i++)
		pthread_join(t[i], NULL);

	section("futex wake_op");
	fword2 = 5;
	start_waiters(t, w, 2, &fword, NULL);
	/* fword2 += 3; wake 1 on fword; wake 1 on fword2 if old > 4 */
	int op = FUTEX_OP(FUTEX_OP_ADD, 3, FUTEX_OP_CMP_GT, 4);
	CHECK(futex(&fword, FUTEX_WAKE_OP_PRIVATE, 1, (void *)1L, &fword2,
		    op) == 1);
	CHECK(fword2 == 8);
	op = FUTEX_OP(FUTEX_OP_SET, 0, FUTEX_OP_CMP_EQ, 1);
	CHECK(futex(&fword2, FUTEX_WAKE_OP_PRIVATE, 1, (void *)1L, &fword,
		    op) == 1);
	CHECK(fword == 0);
	for (int i = 0; i < 2; i++)
		pthread_join(t[i], NULL);
	fword = 1;
}

/* --- signals and threads ------------------------------------------ */

static volatile pid_t handler_tid;
static volatile int handled;

static void on_usr(int sig)
{
	(void)sig;
	handler_tid = gettid_();
	handled++;
}

static volatile pid_t worker_tid;
static volatile int worker_stop;

static void *signal_worker(void *arg)
{
	(void)arg;
	worker_tid = gettid_();
	while (!worker_stop)
		sleep_ms(5);
	return NULL;
}

static void *eintr_worker(void *arg)
{
	struct fwait *w = arg;
	struct timespec ts = { 5, 0 };
	worker_tid = gettid_();
	w->ret = futex(w->addr, FUTEX_WAIT_PRIVATE, w->val, w->bitset ? &ts : NULL,
		       NULL, 0);
	w->err = errno;
	return NULL;
}

static void signals(void)
{
	section("signals and threads");
	struct sigaction sa;
	memset(&sa, 0, sizeof sa);
	sa.sa_handler = on_usr;
	sigaction(SIGUSR1, &sa, NULL);
	sigaction(SIGUSR2, &sa, NULL);

	/* pthread_kill runs the handler in that thread */
	pthread_t t;
	worker_tid = 0;
	worker_stop = 0;
	pthread_create(&t, NULL, signal_worker, NULL);
	while (!worker_tid)
		sleep_ms(1);
	handled = 0;
	CHECK(pthread_kill(t, SIGUSR1) == 0);
	while (!handled)
		sleep_ms(1);
	CHECK(handler_tid == worker_tid);

	/* a process signal goes to a thread that does not block it */
	sigset_t set, old;
	sigemptyset(&set);
	sigaddset(&set, SIGUSR2);
	pthread_sigmask(SIG_BLOCK, &set, &old);
	handled = 0;
	CHECK(kill(getpid(), SIGUSR2) == 0);
	while (!handled)
		sleep_ms(1);
	CHECK(handler_tid == worker_tid);
	pthread_sigmask(SIG_SETMASK, &old, NULL);
	worker_stop = 1;
	pthread_join(t, NULL);

	/* tgkill checks the thread group */
	CHECK(syscall(SYS_tgkill, getpid(), gettid_(), 0) == 0);
	CHECK(syscall(SYS_tgkill, getpid() + 100000, gettid_(), 0) == -1 &&
	      errno == ESRCH);
	CHECK(syscall(SYS_tkill, gettid_(), 0) == 0);

	/* a handler without SA_RESTART interrupts futex waits */
	struct fwait w = { &fword, 1, 0, 0, 0 };
	for (int timed = 0; timed < 2; timed++) {
		fword = 1;
		w.bitset = timed;
		worker_tid = 0;
		pthread_create(&t, NULL, eintr_worker, &w);
		while (!worker_tid)
			sleep_ms(1);
		sleep_ms(50);
		pthread_kill(t, SIGUSR1);
		pthread_join(t, NULL);
		CHECK(w.ret == -1 && w.err == EINTR);
	}
	signal(SIGUSR1, SIG_DFL);
	signal(SIGUSR2, SIG_DFL);
}

/* --- exits ---------------------------------------------------------- */

static void *exit_group_thread(void *arg)
{
	sleep_ms(20);
	exit((int)(long)arg);
}

static void *returner(void *arg)
{
	sleep_ms(50);
	return arg;
}

static void *self_kill(void *arg)
{
	(void)arg;
	sleep_ms(20);
	pthread_kill(pthread_self(), SIGTERM);
	while (!worker_stop)
		pause();
	return NULL;
}

static void exits(void)
{
	section("exits");
	/* exit() in a thread ends the whole process */
	pid_t p = fork();
	if (p == 0) {
		pthread_t t;
		pthread_create(&t, NULL, exit_group_thread, (void *)3L);
		for (;;)
			pause();
	}
	int st = status_of(p);
	CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 3);

	/* the main thread leaves with pthread_exit; the last thread ends it */
	p = fork();
	if (p == 0) {
		pthread_t t;
		pthread_create(&t, NULL, returner, NULL);
		/* (musl's pthread_exit in the main thread of a forked child
		 * hangs on Linux too: leave with the bare system call) */
		syscall(SYS_exit, 0);
	}
	st = status_of(p);
	CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0);

	/* ... or calls exit() later */
	p = fork();
	if (p == 0) {
		pthread_t t;
		pthread_create(&t, NULL, exit_group_thread, (void *)5L);
		syscall(SYS_exit, 0);
	}
	st = status_of(p);
	CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 5);

	/* a fatal signal to one thread kills them all */
	p = fork();
	if (p == 0) {
		pthread_t t[3];
		for (int i = 0; i < 3; i++)
			pthread_create(&t[i], NULL, i ? returner : self_kill,
				       NULL);
		for (;;)
			pause();
	}
	st = status_of(p);
	CHECK(WIFSIGNALED(st) && WTERMSIG(st) == SIGTERM);

	/* SIGKILL from outside */
	p = fork();
	if (p == 0) {
		pthread_t t;
		pthread_create(&t, NULL, signal_worker, NULL);
		for (;;)
			pause();
	}
	sleep_ms(50);
	kill(p, SIGKILL);
	st = status_of(p);
	CHECK(WIFSIGNALED(st) && WTERMSIG(st) == SIGKILL);
}

/* --- robust mutexes ---------------------------------------------- */

static pthread_mutex_t robust;

static void *lock_and_die(void *arg)
{
	(void)arg;
	pthread_mutex_lock(&robust);
	return NULL;
}

static void robust_mutex(void)
{
	section("robust mutex");
	pthread_mutexattr_t a;
	pthread_mutexattr_init(&a);
	pthread_mutexattr_setrobust(&a, PTHREAD_MUTEX_ROBUST);
	pthread_mutex_init(&robust, &a);
	pthread_t t;
	pthread_create(&t, NULL, lock_and_die, NULL);
	pthread_join(t, NULL);
	CHECK(pthread_mutex_lock(&robust) == EOWNERDEAD);
	CHECK(pthread_mutex_consistent(&robust) == 0);
	CHECK(pthread_mutex_unlock(&robust) == 0);
	CHECK(pthread_mutex_lock(&robust) == 0);
	CHECK(pthread_mutex_unlock(&robust) == 0);

	void *head;
	size_t len;
	CHECK(syscall(SYS_get_robust_list, 0, &head, &len) == 0 &&
	      len == 3 * sizeof(long));
}

/* --- /proc and exec ----------------------------------------------- */

static pthread_barrier_t barrier;

static void *park(void *arg)
{
	(void)arg;
	pthread_barrier_wait(&barrier);
	pthread_barrier_wait(&barrier);
	return NULL;
}

static int threads_in_status(void)
{
	FILE *f = fopen("/proc/self/status", "r");
	char line[256];
	int n = -1;
	while (f && fgets(line, sizeof line, f))
		if (sscanf(line, "Threads: %d", &n) == 1)
			break;
	if (f)
		fclose(f);
	return n;
}

static int task_entries(void)
{
	DIR *d = opendir("/proc/self/task");
	if (!d)
		return -1;
	int n = 0;
	struct dirent *e;
	while ((e = readdir(d)))
		if (e->d_name[0] != '.')
			n++;
	closedir(d);
	return n;
}

static void *forever(void *arg)
{
	(void)arg;
	while (!worker_stop)
		pause();
	return NULL;
}

static void proc_and_exec(void)
{
	section("proc and exec");
	pthread_t t[3];
	pthread_barrier_init(&barrier, NULL, 4);
	for (int i = 0; i < 3; i++)
		pthread_create(&t[i], NULL, park, NULL);
	pthread_barrier_wait(&barrier);
	CHECK(threads_in_status() == 4);
	CHECK(task_entries() == 4);
	char path[64];
	snprintf(path, sizeof path, "/proc/self/task/%d/comm", gettid_());
	CHECK(access(path, R_OK) == 0);
	pthread_barrier_wait(&barrier);
	for (int i = 0; i < 3; i++)
		pthread_join(t[i], NULL);
	CHECK(threads_in_status() == 1);

	/* execve from a multithreaded process leaves one thread */
	pid_t p = fork();
	if (p == 0) {
		pthread_t f;
		for (int i = 0; i < 3; i++)
			pthread_create(&f, NULL, forever, NULL);
		execl(self, self, "exec-child", (char *)NULL);
		_exit(99);
	}
	int st = status_of(p);
	CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 1);
}

/* --- scheduling calls ----------------------------------------------- */

static void scheduling(void)
{
	section("scheduling");
	cpu_set_t set;
	CPU_ZERO(&set);
	CHECK(sched_getaffinity(0, sizeof set, &set) == 0);
	CHECK(CPU_COUNT(&set) >= 1);
	CHECK(sched_yield() == 0);
	CHECK(sched_getcpu() >= 0);
}

int main(int argc, char **argv)
{
	self = argv[0];
	if (argc > 1 && strcmp(argv[1], "exec-child") == 0)
		return threads_in_status() == 1 && task_entries() == 1 ? 1 : 2;
	setvbuf(stdout, NULL, _IOLBF, 0);
	create_join();
	contention();
	broadcast();
	tls();
	futexes();
	signals();
	exits();
	robust_mutex();
	proc_and_exec();
	scheduling();
	printf("%s\n", failures ? "FAILED" : "PASSED");
	return failures != 0;
}
