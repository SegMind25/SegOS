/*
 * Phase 8 conformance test: user and PID namespaces, as Chromium's
 * sandbox uses them: unshare and clone with CLONE_NEWUSER and
 * CLONE_NEWPID; uid_map, gid_map and setgroups, written from inside and
 * from outside; ids and file owners as a namespace sees them; pid 1, the
 * numbering of its children, the reaping of orphans and the signals init
 * ignores in a new PID namespace; and the end of the namespace with its
 * init; network namespaces (nothing reachable, abstract unix names of
 * their own); chroot, and CLONE_FS sharing the root, working directory
 * and umask (Chromium chroots its sandbox into a dead process's
 * /proc/<pid>/fdinfo that way). `cargo xtask test` runs it on Linux and on SegOS; both must print
 * exactly namespaces.expected and exit with 0. It never prints an id, so
 * the output is the same whoever runs it.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

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
}

static uid_t outer_uid;
static gid_t outer_gid;
/* A file this program created (so it belongs to the outer uid). */
static char file[64];
static char buf[256];

static int write_file(const char *path, const char *text)
{
	int fd = open(path, O_WRONLY);
	if (fd < 0)
		return -1;
	ssize_t n = write(fd, text, strlen(text));
	int e = errno;
	close(fd);
	errno = e;
	return n == (ssize_t)strlen(text) ? 0 : -1;
}

/* Reads `path` into buf; returns its length or -1. */
static int read_file(const char *path)
{
	int fd = open(path, O_RDONLY);
	if (fd < 0)
		return -1;
	ssize_t n = read(fd, buf, sizeof buf - 1);
	close(fd);
	if (n < 0)
		return -1;
	buf[n] = 0;
	return (int)n;
}

/* Whether buf is one map line, as Linux prints it. */
static int is_map(unsigned first, unsigned lower, unsigned count)
{
	char want[64];
	snprintf(want, sizeof want, "%10u %10u %10u\n", first, lower, count);
	return strcmp(buf, want) == 0;
}

static uid_t file_uid(void)
{
	struct stat st;
	return stat(file, &st) == 0 ? st.st_uid : (uid_t)-2;
}

static void ns_link(const char *name, char *out, size_t size)
{
	char path[64];
	snprintf(path, sizeof path, "/proc/self/ns/%s", name);
	ssize_t n = readlink(path, out, size - 1);
	out[n > 0 ? n : 0] = 0;
}

static int in_child(void (*fn)(void))
{
	fflush(stdout);
	pid_t pid = fork();
	if (pid == 0) {
		fn();
		fflush(stdout);
		_exit(failures ? 1 : 0);
	}
	int status = 0;
	waitpid(pid, &status, 0);
	return status;
}

/* --- user namespaces ------------------------------------------------ */

static void initial(void)
{
	CHECK(read_file("/proc/self/uid_map") > 0 && is_map(0, 0, 4294967295u));
	CHECK(read_file("/proc/self/gid_map") > 0 && is_map(0, 0, 4294967295u));
	CHECK(read_file("/proc/self/setgroups") > 0 && strcmp(buf, "allow\n") == 0);
	CHECK(write_file("/proc/self/uid_map", "0 0 1") == -1 && errno == EPERM);
	/* A user namespace cannot share filesystem state, a new namespace
	 * cannot share the thread group. */
	CHECK(syscall(SYS_clone, CLONE_NEWUSER | CLONE_FS | SIGCHLD, 0, 0, 0, 0) == -1 &&
	      errno == EINVAL);
	CHECK(syscall(SYS_clone, CLONE_NEWPID | CLONE_THREAD | CLONE_SIGHAND | CLONE_VM, 0, 0, 0, 0) == -1 &&
	      errno == EINVAL);
}

static void user_ns(void)
{
	char before[64], after[64], line[64];
	ns_link("user", before, sizeof before);
	CHECK(unshare(CLONE_NEWUSER) == 0);
	ns_link("user", after, sizeof after);
	CHECK(strncmp(after, "user:[", 6) == 0 && strcmp(before, after) != 0);
	/* Nothing is mapped yet: every id is the overflow id. */
	CHECK(getuid() == 65534 && geteuid() == 65534 && getgid() == 65534);
	CHECK(file_uid() == 65534);
	CHECK(read_file("/proc/self/uid_map") == 0);
	CHECK(read_file("/proc/self/setgroups") > 0 && strcmp(buf, "allow\n") == 0);
	/* Only our own ids, and our group only once setgroups is denied. */
	snprintf(line, sizeof line, "0 %u 1", outer_gid);
	CHECK(write_file("/proc/self/gid_map", line) == -1 && errno == EPERM);
	CHECK(write_file("/proc/self/setgroups", "deny") == 0);
	CHECK(write_file("/proc/self/gid_map", line) == 0);
	CHECK(write_file("/proc/self/setgroups", "allow") == -1 && errno == EPERM);
	snprintf(line, sizeof line, "0 %u 2", outer_uid);
	CHECK(write_file("/proc/self/uid_map", line) == -1 && errno == EPERM);
	CHECK(write_file("/proc/self/uid_map", "0 0 x") == -1 && errno == EINVAL);
	snprintf(line, sizeof line, "0 %u 1\n", outer_uid);
	CHECK(write_file("/proc/self/uid_map", line) == 0);
	CHECK(write_file("/proc/self/uid_map", line) == -1 && errno == EPERM);
	/* Root inside; our file is root's. */
	CHECK(getuid() == 0 && geteuid() == 0 && getgid() == 0 && getegid() == 0);
	CHECK(file_uid() == 0);
	CHECK(read_file("/proc/self/uid_map") > 0 && is_map(0, outer_uid, 1));
	CHECK(read_file("/proc/self/gid_map") > 0 && is_map(0, outer_gid, 1));
	CHECK(read_file("/proc/self/setgroups") > 0 && strcmp(buf, "deny\n") == 0);
	CHECK(setgroups(0, NULL) == -1 && errno == EPERM);
	CHECK(setuid(0) == 0 && setgid(0) == 0 && setresuid(-1, 0, -1) == 0);
	CHECK(setuid(1) == -1 && errno == EINVAL);
	CHECK(chown(file, 0, 0) == 0);
	CHECK(chown(file, 7, -1) == -1 && errno == EINVAL);
}

/* The parent maps a child's namespace (as Chromium's browser process
 * does for its sandboxed children). */
static void mapped_from_outside(void)
{
	int ready[2], go[2];
	char c, path[64], line[64];
	if (pipe(ready) || pipe(go))
		return;
	fflush(stdout);
	pid_t pid = fork();
	if (pid == 0) {
		if (unshare(CLONE_NEWUSER) != 0)
			_exit(2);
		if (write(ready[1], "r", 1) != 1 || read(go[0], &c, 1) != 1)
			_exit(3);
		_exit(getuid() == 5 && geteuid() == 5 ? 0 : 4);
	}
	CHECK(read(ready[0], &c, 1) == 1);
	snprintf(path, sizeof path, "/proc/%d/uid_map", pid);
	snprintf(line, sizeof line, "5 %u 1", outer_uid);
	CHECK(write_file(path, line) == 0);
	CHECK(read_file(path) > 0 && is_map(5, outer_uid, 1));
	CHECK(write(go[1], "g", 1) == 1);
	int status = 0;
	CHECK(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static int thread_go[2];

static void *waiter(void *arg)
{
	char c;
	if (read(thread_go[0], &c, 1) != 1)
		return NULL;
	return arg;
}

static void threaded(void)
{
	pthread_t t;
	if (pipe(thread_go))
		return;
	CHECK(pthread_create(&t, NULL, waiter, NULL) == 0);
	/* Only a single-threaded process can change its user namespace. */
	CHECK(unshare(CLONE_NEWUSER) == -1 && errno == EINVAL);
	CHECK(write(thread_go[1], "x", 1) == 1 && pthread_join(t, NULL) == 0);
}

/* --- PID namespaces -------------------------------------------------- */

/* The init's last child keeps this pipe's write end open; init starts
 * printing when a byte arrives on `start` (after the parent's lines). */
static int held[2], start[2];

static void ns_init(void)
{
	char link[64], kids[64];
	int status;
	if (read(start[0], link, 1) != 1)
		return;
	CHECK(getpid() == 1 && getppid() == 0 && syscall(SYS_gettid) == 1);
	ns_link("pid", link, sizeof link);
	ns_link("pid_for_children", kids, sizeof kids);
	CHECK(strncmp(link, "pid:[", 5) == 0 && strcmp(link, kids) == 0);
	/* The process group and session are outside the namespace. */
	CHECK(getpgid(0) == 0 && getsid(0) == 0);
	CHECK(setsid() == 1 && getpgid(0) == 1 && getsid(0) == 1);
	/* Signals with the default action do not reach init from inside. */
	CHECK(kill(1, SIGTERM) == 0 && raise(SIGUSR1) == 0);
	CHECK(kill(1, 0) == 0 && kill(-1, 0) == -1 && errno == ESRCH);

	/* Its children are numbered from 2. */
	fflush(stdout);
	pid_t c = fork();
	if (c == 0)
		_exit(getpid() == 2 && getppid() == 1 ? 0 : 1);
	CHECK(c == 2 && waitpid(c, &status, 0) == 2 && WIFEXITED(status) &&
	      WEXITSTATUS(status) == 0);

	/* An orphan goes to init. */
	int p[2];
	if (pipe(p))
		return;
	fflush(stdout);
	pid_t mid = fork();
	if (mid == 0) {
		if (fork() == 0) {
			char ch;
			close(p[1]);
			if (read(p[0], &ch, 1) != 1)
				_exit(2);
			_exit(getppid() == 1 ? 0 : 1);
		}
		_exit(0);
	}
	CHECK(mid == 3 && waitpid(mid, &status, 0) == 3 && WIFEXITED(status));
	CHECK(write(p[1], "x", 1) == 1);
	CHECK(waitpid(-1, &status, 0) == 4 && WIFEXITED(status) && WEXITSTATUS(status) == 0);
	close(p[0]);
	close(p[1]);

	/* This one outlives init: it is killed when init exits. */
	fflush(stdout);
	pid_t sleeper = fork();
	if (sleeper == 0) {
		for (;;)
			pause();
	}
	close(held[1]);
	CHECK(sleeper == 5 && kill(5, 0) == 0);
}

static void pid_ns(void)
{
	char before[64], after[64], kids[64], path[64], theirs[64];
	pid_t me = getpid();
	pthread_t t;
	int status = 0;
	ns_link("pid", before, sizeof before);
	CHECK(unshare(CLONE_NEWUSER | CLONE_NEWPID) == 0);
	ns_link("pid", after, sizeof after);
	/* The caller stays where it is; its children go to the new one,
	 * which has no name until its first process exists. */
	CHECK(getpid() == me && strcmp(before, after) == 0);
	CHECK(readlink("/proc/self/ns/pid_for_children", kids, sizeof kids) == -1 &&
	      errno == ENOENT);
	CHECK(unshare(CLONE_NEWPID) == -1 && errno == EINVAL);
	/* Threads must stay in their process's PID namespace. */
	CHECK(pthread_create(&t, NULL, waiter, NULL) != 0);
	if (pipe(held) || pipe(start))
		return;
	fflush(stdout);
	pid_t init = fork();
	if (init == 0) {
		ns_init();
		fflush(stdout);
		_exit(failures ? 1 : 0);
	}
	close(held[1]);
	ns_link("pid_for_children", kids, sizeof kids);
	snprintf(path, sizeof path, "/proc/%d/ns/pid", init);
	ssize_t n = readlink(path, theirs, sizeof theirs - 1);
	theirs[n > 0 ? n : 0] = 0;
	CHECK(strcmp(kids, theirs) == 0 && strcmp(kids, after) != 0);
	/* From outside too, default-action signals other than SIGKILL and
	 * SIGSTOP do not reach it. */
	CHECK(init > 1 && kill(init, SIGUSR2) == 0);
	CHECK(write(start[1], "s", 1) == 1);
	CHECK(waitpid(init, &status, 0) == init && WIFEXITED(status) && WEXITSTATUS(status) == 0);
	/* The rest of the namespace went with its init. */
	struct pollfd pfd = {held[0], POLLIN, 0};
	char c;
	CHECK(poll(&pfd, 1, 20000) == 1 && read(held[0], &c, 1) == 0);
	/* Nothing can start in it any more. */
	CHECK(fork() == -1 && errno == ENOMEM);
}

/* --- network namespaces ---------------------------------------------- */

static const char abstract_name[] = "\0segos-namespaces-test";

static int unix_socket_at(int (*op)(int, const struct sockaddr *, socklen_t))
{
	struct sockaddr_un a = {.sun_family = AF_UNIX};
	memcpy(a.sun_path, abstract_name, sizeof abstract_name - 1);
	int s = socket(AF_UNIX, SOCK_STREAM, 0);
	socklen_t len = offsetof(struct sockaddr_un, sun_path) + sizeof abstract_name - 1;
	if (op(s, (struct sockaddr *)&a, len) != 0) {
		int e = errno;
		close(s);
		errno = e;
		return -1;
	}
	return s;
}

static void net_ns(void)
{
	char before[64], after[64];
	struct sockaddr_in lo = {.sin_family = AF_INET, .sin_port = htons(9)};
	struct sockaddr_in any = {.sin_family = AF_INET};
	socklen_t len = sizeof any;
	lo.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	ns_link("net", before, sizeof before);
	CHECK(unshare(CLONE_NEWUSER | CLONE_NEWNET) == 0);
	ns_link("net", after, sizeof after);
	CHECK(strncmp(after, "net:[", 5) == 0 && strcmp(before, after) != 0);
	/* Only a loopback interface, down: nothing to reach or bind. */
	int t = socket(AF_INET, SOCK_STREAM, 0);
	CHECK(t >= 0 && connect(t, (struct sockaddr *)&lo, sizeof lo) == -1 && errno == ENETUNREACH);
	close(t);
	int u = socket(AF_INET, SOCK_DGRAM, 0);
	CHECK(u >= 0 && sendto(u, "x", 1, 0, (struct sockaddr *)&lo, sizeof lo) == -1 &&
	      errno == ENETUNREACH);
	close(u);
	u = socket(AF_INET, SOCK_DGRAM, 0);
	CHECK(bind(u, (struct sockaddr *)&lo, sizeof lo) == 0 &&
	      getsockname(u, (struct sockaddr *)&any, &len) == 0 && any.sin_port == htons(9));
	close(u);
	/* The parent's abstract name is not here; this namespace can have
	 * its own. */
	CHECK(unix_socket_at(connect) == -1 && errno == ECONNREFUSED);
	int mine = unix_socket_at(bind);
	CHECK(mine >= 0 && listen(mine, 1) == 0);
	int c = unix_socket_at(connect);
	CHECK(c >= 0);
	close(c);
	close(mine);
}

static void net(void)
{
	int s = unix_socket_at(bind);
	CHECK(s >= 0 && listen(s, 1) == 0);
	int status = in_child(net_ns);
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	close(s);
}

/* --- chroot and CLONE_FS --------------------------------------------- */

static char dir[] = "/tmp/nsXXXXXX";

/* fork() that shares the filesystem state with the parent. */
static pid_t fork_fs(void)
{
	fflush(stdout);
	return syscall(SYS_clone, CLONE_FS | SIGCHLD, 0, 0, 0, 0);
}

static void chroot_fs(void)
{
	char cwd[64], sub[80];
	struct stat a, b;
	int status;
	CHECK(unshare(CLONE_NEWUSER) == 0);
	/* A child sharing our filesystem state moves our working directory
	 * and sets our umask. */
	pid_t pid = fork_fs();
	if (pid == 0)
		_exit(chdir(dir) == 0 && umask(077) == 022 ? 0 : 1);
	CHECK(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0);
	CHECK(getcwd(cwd, sizeof cwd) && strcmp(cwd, dir) == 0 && umask(022) == 077);
	/* chroot: "/" is the directory, and ".." stops there. */
	snprintf(sub, sizeof sub, "%s/sub", dir);
	CHECK(mkdir(sub, 0755) == 0 && chroot(dir) == 0 && chdir("/") == 0);
	CHECK(stat("/sub", &a) == 0 && stat("/../sub", &b) == 0 && a.st_ino == b.st_ino);
	CHECK(stat("/f", &a) == 0 && stat("/tmp", &b) == -1 && errno == ENOENT);
	CHECK(rmdir("/sub") == 0);
}

/* Chromium's way into an empty root: a CLONE_FS child chroots into its
 * own /proc/self/fdinfo, which is empty once it is gone. */
static void chromium_chroot(void)
{
	int status;
	CHECK(unshare(CLONE_NEWUSER) == 0);
	pid_t pid = fork_fs();
	if (pid == 0)
		_exit(chroot("/proc/self/fdinfo/") == 0 && chdir("/") == 0 ? 0 : 1);
	CHECK(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0);
	CHECK(open("/etc/passwd", O_RDONLY) == -1 && errno == ESRCH);
}

int main(void)
{
	setvbuf(stdout, NULL, _IOLBF, 0);
	outer_uid = getuid();
	outer_gid = getgid();
	if (!mkdtemp(dir))
		return 2;
	snprintf(file, sizeof file, "%s/f", dir);
	close(open(file, O_CREAT | O_WRONLY, 0644));
	int status;
	section("initial namespaces");
	initial();
	section("user namespace");
	status = in_child(user_ns);
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	section("mapped from outside");
	mapped_from_outside();
	section("threads");
	status = in_child(threaded);
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	section("pid namespace");
	status = in_child(pid_ns);
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	section("network namespace");
	net();
	section("chroot and CLONE_FS");
	status = in_child(chroot_fs);
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	status = in_child(chromium_chroot);
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	unlink(file);
	rmdir(dir);
	printf("%s\n", failures ? "FAILED" : "PASSED");
	return failures ? 1 : 0;
}
