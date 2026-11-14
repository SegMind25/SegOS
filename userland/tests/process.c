/*
 * Phase 3 conformance test: processes, pipes and signals. `cargo xtask
 * test` runs it on Linux and on SegOS; both must print exactly
 * process.expected and exit with 0. No pids or times in the output.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <setjmp.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;
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

static int status_of(pid_t p)
{
	int st = -1;
	waitpid(p, &st, 0);
	return st;
}

static void fork_wait(void)
{
	printf("# fork and wait\n");
	fflush(stdout);
	pid_t p = fork();
	if (p == 0)
		_exit(7);
	CHECK(p > 0);
	int st;
	CHECK(waitpid(p, &st, 0) == p);
	CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 7);
	CHECK(waitpid(-1, &st, WNOHANG) == -1 && errno == ECHILD);
	p = fork();
	if (p == 0) {
		usleep(50000);
		_exit(0);
	}
	CHECK(waitpid(p, &st, WNOHANG) == 0);
	CHECK(waitpid(p, &st, 0) == p && WIFEXITED(st));
}

static int global = 1;

static void cow(void)
{
	printf("# copy-on-write\n");
	char *heap = malloc(100000);
	memset(heap, 'p', 100000);
	int fds[2];
	CHECK(pipe(fds) == 0);
	fflush(stdout);
	pid_t p = fork();
	if (p == 0) {
		global = 2;
		memset(heap, 'c', 100000);
		char ok = global == 2 && heap[0] == 'c' && heap[99999] == 'c';
		write(fds[1], &ok, 1);
		_exit(0);
	}
	char ok = 0;
	CHECK(read(fds[0], &ok, 1) == 1 && ok == 1);
	status_of(p);
	CHECK(global == 1);
	CHECK(heap[0] == 'p' && heap[99999] == 'p');
	close(fds[0]);
	close(fds[1]);
	free(heap);
}

static void pipes(void)
{
	printf("# pipes\n");
	int fds[2];
	char buf[4096];
	CHECK(pipe(fds) == 0);
	fflush(stdout);
	pid_t p = fork();
	if (p == 0) {
		close(fds[0]);
		for (int i = 0; i < 2000; i++)
			write(fds[1], "0123456789", 10);
		_exit(0);
	}
	close(fds[1]);
	long total = 0;
	ssize_t n;
	while ((n = read(fds[0], buf, sizeof buf)) > 0)
		total += n;
	CHECK(n == 0 && total == 20000);
	status_of(p);
	close(fds[0]);

	CHECK(pipe(fds) == 0);
	close(fds[0]);
	signal(SIGPIPE, SIG_IGN);
	CHECK(write(fds[1], "x", 1) == -1 && errno == EPIPE);
	signal(SIGPIPE, SIG_DFL);
	close(fds[1]);

	CHECK(pipe2(fds, O_NONBLOCK | O_CLOEXEC) == 0);
	CHECK(read(fds[0], buf, 1) == -1 && errno == EAGAIN);
	CHECK(fcntl(fds[0], F_GETFD) == FD_CLOEXEC);
	struct pollfd pf = { fds[0], POLLIN, 0 };
	CHECK(poll(&pf, 1, 0) == 0);
	CHECK(write(fds[1], "y", 1) == 1);
	CHECK(poll(&pf, 1, 1000) == 1 && (pf.revents & POLLIN));
	close(fds[1]);
	CHECK(read(fds[0], buf, 2) == 1 && read(fds[0], buf, 1) == 0);
	CHECK(poll(&pf, 1, 0) == 1 && (pf.revents & POLLHUP));
	close(fds[0]);
}

static volatile sig_atomic_t got;
static void handler(int s)
{
	got = s;
}

static sigjmp_buf jump;
static void on_segv(int s)
{
	siglongjmp(jump, s);
}

/* Blocks in read() on a pipe while a child sends SIGUSR1; returns what
 * read() returned. */
static ssize_t interrupted_read(int restart)
{
	struct sigaction sa = { 0 };
	sa.sa_handler = handler;
	sa.sa_flags = restart ? SA_RESTART : 0;
	sigaction(SIGUSR1, &sa, NULL);
	int fds[2];
	pipe(fds);
	got = 0;
	fflush(stdout);
	pid_t parent = getpid(), p = fork();
	if (p == 0) {
		usleep(100000);
		kill(parent, SIGUSR1);
		usleep(100000);
		write(fds[1], "z", 1);
		_exit(0);
	}
	char c;
	ssize_t r = read(fds[0], &c, 1);
	int e = errno;
	if (r < 0)
		read(fds[0], &c, 1); /* collect the byte */
	status_of(p);
	close(fds[0]);
	close(fds[1]);
	errno = e;
	return r;
}

static void signals(void)
{
	printf("# signals\n");
	struct sigaction sa = { 0 };
	sa.sa_handler = handler;
	sigaction(SIGUSR1, &sa, NULL);
	got = 0;
	CHECK(kill(getpid(), SIGUSR1) == 0 && got == SIGUSR1);

	sigset_t s, old, pend;
	sigemptyset(&s);
	sigaddset(&s, SIGUSR1);
	got = 0;
	sigprocmask(SIG_BLOCK, &s, &old);
	raise(SIGUSR1);
	CHECK(got == 0);
	sigpending(&pend);
	CHECK(sigismember(&pend, SIGUSR1));
	sigprocmask(SIG_SETMASK, &old, NULL);
	CHECK(got == SIGUSR1);

	signal(SIGUSR2, SIG_IGN);
	CHECK(raise(SIGUSR2) == 0);
	signal(SIGUSR2, SIG_DFL);

	ssize_t r = interrupted_read(1);
	CHECK(r == 1 && got == SIGUSR1);
	r = interrupted_read(0);
	int e = errno;
	CHECK(r == -1 && e == EINTR && got == SIGUSR1);

	sa.sa_handler = on_segv;
	sigaction(SIGSEGV, &sa, NULL);
	int *volatile bad = (int *)16;
	int where = sigsetjmp(jump, 1);
	if (where == 0)
		*bad = 1;
	CHECK(where == SIGSEGV);
	signal(SIGSEGV, SIG_DFL);

	fflush(stdout);
	pid_t p = fork();
	if (p == 0) {
		pause();
		_exit(0);
	}
	usleep(20000);
	kill(p, SIGTERM);
	int st = status_of(p);
	CHECK(WIFSIGNALED(st) && WTERMSIG(st) == SIGTERM);

	p = fork();
	if (p == 0) {
		raise(SIGSTOP);
		_exit(3);
	}
	CHECK(waitpid(p, &st, WUNTRACED) == p && WIFSTOPPED(st) && WSTOPSIG(st) == SIGSTOP);
	kill(p, SIGCONT);
	CHECK(waitpid(p, &st, 0) == p && WIFEXITED(st) && WEXITSTATUS(st) == 3);

	got = 0;
	sa.sa_handler = handler;
	sigaction(SIGCHLD, &sa, NULL);
	sigemptyset(&s);
	sigaddset(&s, SIGCHLD);
	sigprocmask(SIG_BLOCK, &s, &old);
	p = fork();
	if (p == 0)
		_exit(0);
	while (!got)
		sigsuspend(&old);
	CHECK(got == SIGCHLD);
	status_of(p);
	sigprocmask(SIG_SETMASK, &old, NULL);
	signal(SIGCHLD, SIG_DFL);
}

static void exec(void)
{
	printf("# exec\n");
	fflush(stdout);
	pid_t p = fork();
	if (p == 0) {
		execl(self, self, "child", NULL);
		_exit(99);
	}
	int st = status_of(p);
	CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 42);
	CHECK(execl("/no/such/program", "x", (char *)NULL) == -1 && errno == ENOENT);

	p = vfork();
	if (p == 0)
		_exit(5);
	st = status_of(p);
	CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 5);

	char *argv[] = { self, "child", NULL };
	CHECK(posix_spawn(&p, self, NULL, NULL, argv, environ) == 0);
	st = status_of(p);
	CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 42);

	int fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
	char num[16];
	snprintf(num, sizeof num, "%d", fd);
	fflush(stdout);
	p = fork();
	if (p == 0) {
		execl(self, self, "closed", num, NULL);
		_exit(99);
	}
	st = status_of(p);
	CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 43);
	close(fd);
}

static void groups(void)
{
	printf("# process groups and sessions\n");
	CHECK(getpgid(0) == getpgrp());
	CHECK(getsid(0) > 0);
	fflush(stdout);
	pid_t p = fork();
	if (p == 0)
		_exit(setpgid(0, 0) == 0 && getpgrp() == getpid() ? 0 : 1);
	CHECK(WEXITSTATUS(status_of(p)) == 0);
	p = fork();
	if (p == 0)
		_exit(setsid() == getpid() && getsid(0) == getpid() ? 0 : 1);
	CHECK(WEXITSTATUS(status_of(p)) == 0);
	CHECK(kill(-getpgrp(), 0) == 0);
	CHECK(kill(999999, 0) == -1 && errno == ESRCH);
}

int main(int argc, char **argv)
{
	self = argv[0];
	if (argc > 1 && strcmp(argv[1], "child") == 0)
		return 42;
	if (argc > 2 && strcmp(argv[1], "closed") == 0)
		return fcntl(atoi(argv[2]), F_GETFD) == -1 && errno == EBADF ? 43 : 1;
	fork_wait();
	cow();
	pipes();
	signals();
	exec();
	groups();
	printf("%d failures\n", failures);
	return failures ? 1 : 0;
}
