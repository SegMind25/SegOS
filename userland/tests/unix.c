/*
 * Phase 6 conformance test: Unix domain sockets. `cargo xtask test` runs
 * it on Linux and on SegOS; both must print exactly unix.expected.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
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
	} while (0)

static socklen_t addr(struct sockaddr_un *a, const char *path, int abstract)
{
	memset(a, 0, sizeof *a);
	a->sun_family = AF_UNIX;
	if (abstract) {
		memcpy(a->sun_path + 1, path, strlen(path));
		return offsetof(struct sockaddr_un, sun_path) + 1 + strlen(path);
	}
	strcpy(a->sun_path, path);
	return sizeof *a;
}

static void pairs(void)
{
	printf("# socketpair\n");
	int sv[2];
	char buf[64] = { 0 };
	CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	CHECK(write(sv[0], "hello", 5) == 5);
	CHECK(write(sv[0], " world", 6) == 6);
	int n = 0;
	CHECK(ioctl(sv[1], FIONREAD, &n) == 0 && n == 11);
	CHECK(recv(sv[1], buf, sizeof buf, MSG_PEEK) == 11);
	CHECK(read(sv[1], buf, sizeof buf) == 11 && memcmp(buf, "hello world", 11) == 0);
	CHECK(recv(sv[1], buf, sizeof buf, MSG_DONTWAIT) == -1 && errno == EAGAIN);
	CHECK(shutdown(sv[0], SHUT_WR) == 0);
	CHECK(read(sv[1], buf, sizeof buf) == 0); /* end of file */
	CHECK(write(sv[1], "back", 4) == 4); /* the other direction still works */
	CHECK(read(sv[0], buf, sizeof buf) == 4);
	close(sv[1]);
	CHECK(send(sv[0], "x", 1, MSG_NOSIGNAL) == -1 && errno == EPIPE);
	close(sv[0]);

	CHECK(socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) == 0);
	CHECK(send(sv[0], "one", 3, 0) == 3);
	CHECK(send(sv[0], "two!", 4, 0) == 4);
	CHECK(recv(sv[1], buf, 2, 0) == 2); /* the rest of "one" is lost */
	CHECK(recv(sv[1], buf, sizeof buf, 0) == 4 && memcmp(buf, "two!", 4) == 0);
	close(sv[0]);
	close(sv[1]);

	CHECK(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv) == 0);
	CHECK(send(sv[0], "abc", 3, 0) == 3 && send(sv[0], "de", 2, 0) == 2);
	CHECK(recv(sv[1], buf, sizeof buf, 0) == 3);
	CHECK(recv(sv[1], buf, sizeof buf, 0) == 2);
	close(sv[0]);
	close(sv[1]);
}

static void named(int abstract)
{
	printf("# %s names\n", abstract ? "abstract" : "file-system");
	const char *path = abstract ? "segos-test-abstract" : "/tmp/segos-test.sock";
	struct sockaddr_un a, got;
	socklen_t len = addr(&a, path, abstract);
	unlink(path);
	int srv = socket(AF_UNIX, SOCK_STREAM, 0);
	CHECK(srv >= 0);
	CHECK(bind(srv, (struct sockaddr *)&a, len) == 0);
	if (!abstract) {
		struct stat st;
		CHECK(stat(path, &st) == 0 && S_ISSOCK(st.st_mode));
	}
	int again = socket(AF_UNIX, SOCK_STREAM, 0);
	CHECK(bind(again, (struct sockaddr *)&a, len) == -1 && errno == EADDRINUSE);
	close(again);
	int c = socket(AF_UNIX, SOCK_STREAM, 0);
	CHECK(connect(c, (struct sockaddr *)&a, len) == -1 && errno == ECONNREFUSED);
	close(c);
	CHECK(listen(srv, 4) == 0);
	c = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	CHECK(connect(c, (struct sockaddr *)&a, len) == 0);
	struct pollfd p = { .fd = srv, .events = POLLIN };
	CHECK(poll(&p, 1, 1000) == 1 && (p.revents & POLLIN));
	int s = accept4(srv, NULL, NULL, SOCK_NONBLOCK);
	CHECK(s >= 0);
	CHECK(read(s, &p, 1) == -1 && errno == EAGAIN);
	CHECK(write(c, "ping", 4) == 4);
	char buf[16] = { 0 };
	CHECK(read(s, buf, sizeof buf) == 4 && memcmp(buf, "ping", 4) == 0);
	len = sizeof got;
	CHECK(getsockname(srv, (struct sockaddr *)&got, &len) == 0 && got.sun_family == AF_UNIX);
	if (!abstract)
		CHECK(strcmp(got.sun_path, path) == 0);
	len = sizeof got;
	CHECK(getpeername(c, (struct sockaddr *)&got, &len) == 0);
	if (!abstract)
		CHECK(strcmp(got.sun_path, path) == 0);
	struct ucred cr;
	len = sizeof cr;
	CHECK(getsockopt(s, SOL_SOCKET, SO_PEERCRED, &cr, &len) == 0 && cr.pid == getpid());
	int type = 0;
	len = sizeof type;
	CHECK(getsockopt(s, SOL_SOCKET, SO_TYPE, &type, &len) == 0 && type == SOCK_STREAM);
	close(c);
	CHECK(read(s, buf, sizeof buf) == 0);
	close(s);
	close(srv);
	if (!abstract)
		CHECK(unlink(path) == 0);
}

static void rights(void)
{
	printf("# passing descriptors\n");
	int sv[2], pipefd[2];
	CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	CHECK(pipe(pipefd) == 0);
	char cbuf[CMSG_SPACE(sizeof(int))] = { 0 };
	struct iovec iov = { .iov_base = "F", .iov_len = 1 };
	struct msghdr m = { .msg_iov = &iov, .msg_iovlen = 1, .msg_control = cbuf,
			    .msg_controllen = sizeof cbuf };
	struct cmsghdr *c = CMSG_FIRSTHDR(&m);
	c->cmsg_level = SOL_SOCKET;
	c->cmsg_type = SCM_RIGHTS;
	c->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(c), &pipefd[1], sizeof(int));
	CHECK(sendmsg(sv[0], &m, 0) == 1);
	close(pipefd[1]);

	char data = 0;
	char rbuf[CMSG_SPACE(sizeof(int))] = { 0 };
	struct iovec riov = { .iov_base = &data, .iov_len = 1 };
	struct msghdr r = { .msg_iov = &riov, .msg_iovlen = 1, .msg_control = rbuf,
			    .msg_controllen = sizeof rbuf };
	CHECK(recvmsg(sv[1], &r, MSG_CMSG_CLOEXEC) == 1 && data == 'F');
	struct cmsghdr *rc = CMSG_FIRSTHDR(&r);
	CHECK(rc != NULL && rc->cmsg_level == SOL_SOCKET && rc->cmsg_type == SCM_RIGHTS);
	int got = -1;
	memcpy(&got, CMSG_DATA(rc), sizeof got);
	CHECK(got >= 0);
	CHECK(fcntl(got, F_GETFD) == FD_CLOEXEC);
	/* The received descriptor is the pipe's write end. */
	CHECK(write(got, "via", 3) == 3);
	char buf[8] = { 0 };
	CHECK(read(pipefd[0], buf, sizeof buf) == 3 && memcmp(buf, "via", 3) == 0);
	close(got);
	close(pipefd[0]);
	close(sv[0]);
	close(sv[1]);
}

static void across_fork(void)
{
	printf("# across fork\n");
	int sv[2];
	CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	pid_t child = fork();
	if (child == 0) {
		close(sv[0]);
		char buf[32];
		ssize_t n = read(sv[1], buf, sizeof buf);
		for (ssize_t i = 0; i < n; i++)
			buf[i] = buf[i] >= 'a' && buf[i] <= 'z' ? buf[i] - 32 : buf[i];
		write(sv[1], buf, n);
		_exit(0);
	}
	close(sv[1]);
	char buf[32] = { 0 };
	CHECK(write(sv[0], "upper case", 10) == 10);
	CHECK(read(sv[0], buf, sizeof buf) == 10 && memcmp(buf, "UPPER CASE", 10) == 0);
	int st;
	CHECK(waitpid(child, &st, 0) == child);
	close(sv[0]);
}

static void errors(void)
{
	printf("# errors\n");
	CHECK(socket(AF_UNIX, 99, 0) == -1);
	int fd = open("/tmp", O_RDONLY);
	CHECK(listen(fd, 1) == -1 && errno == ENOTSOCK);
	close(fd);
	int s = socket(AF_UNIX, SOCK_STREAM, 0);
	CHECK(listen(s, 1) == -1 && errno == EINVAL); /* not bound */
	CHECK(send(s, "x", 1, MSG_NOSIGNAL) == -1 && errno == ENOTCONN);
	struct sockaddr_un a;
	socklen_t len = addr(&a, "/tmp/segos-test-missing.sock", 0);
	CHECK(connect(s, (struct sockaddr *)&a, len) == -1 && errno == ENOENT);
	close(s);
}

int main(void)
{
	signal(SIGPIPE, SIG_IGN);
	pairs();
	named(0);
	named(1);
	rights();
	across_fork();
	errors();
	printf("%s\n", failures ? "FAILED" : "PASSED");
	return failures != 0;
}
