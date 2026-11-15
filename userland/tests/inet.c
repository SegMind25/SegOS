/*
 * Phase 6 conformance test: TCP and UDP sockets over the loopback
 * interface. `cargo xtask test` runs it on Linux and on SegOS; both must
 * print exactly inet.expected.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
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

static struct sockaddr_in loopback(int port)
{
	struct sockaddr_in a;
	memset(&a, 0, sizeof a);
	a.sin_family = AF_INET;
	a.sin_port = htons(port);
	a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	return a;
}

static int port_of(int fd, int peer)
{
	struct sockaddr_in a;
	socklen_t len = sizeof a;
	if ((peer ? getpeername : getsockname)(fd, (struct sockaddr *)&a, &len) < 0)
		return -1;
	return ntohs(a.sin_port);
}

static int opt(int fd, int level, int name)
{
	int v = -1;
	socklen_t len = sizeof v;
	if (getsockopt(fd, level, name, &v, &len) < 0)
		return -1;
	return v;
}

static void tcp(void)
{
	char buf[256];
	int n = 0;
	puts("# tcp");
	int s = socket(AF_INET, SOCK_STREAM, 0);
	CHECK(s >= 0);
	struct sockaddr_in a = loopback(0);
	CHECK(bind(s, (struct sockaddr *)&a, sizeof a) == 0);
	int port = port_of(s, 0);
	CHECK(port > 0);
	CHECK(opt(s, SOL_SOCKET, SO_ACCEPTCONN) == 0);
	CHECK(listen(s, 4) == 0);
	CHECK(opt(s, SOL_SOCKET, SO_ACCEPTCONN) == 1);
	CHECK(opt(s, SOL_SOCKET, SO_TYPE) == SOCK_STREAM);

	int other = socket(AF_INET, SOCK_STREAM, 0);
	a = loopback(port);
	CHECK(bind(other, (struct sockaddr *)&a, sizeof a) == -1 && errno == EADDRINUSE);
	close(other);

	int c = socket(AF_INET, SOCK_STREAM, 0);
	CHECK(port_of(c, 1) == -1 && errno == ENOTCONN);
	CHECK(connect(c, (struct sockaddr *)&a, sizeof a) == 0);
	CHECK(port_of(c, 1) == port);
	struct pollfd p = {.fd = s, .events = POLLIN};
	CHECK(poll(&p, 1, 2000) == 1 && (p.revents & POLLIN));
	struct sockaddr_in peer;
	socklen_t plen = sizeof peer;
	int x = accept(s, (struct sockaddr *)&peer, &plen);
	CHECK(x >= 0);
	CHECK(plen == sizeof peer && peer.sin_family == AF_INET);
	CHECK(peer.sin_addr.s_addr == htonl(INADDR_LOOPBACK));
	CHECK(ntohs(peer.sin_port) == port_of(c, 0));
	CHECK(port_of(x, 0) == port);

	int one = 1;
	CHECK(setsockopt(c, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one) == 0);
	CHECK(send(c, "hello", 5, 0) == 5);
	CHECK(send(c, " world", 6, 0) == 6);
	p = (struct pollfd){.fd = x, .events = POLLIN};
	CHECK(poll(&p, 1, 2000) == 1);
	usleep(100000);
	CHECK(ioctl(x, FIONREAD, &n) == 0 && n == 11);
	CHECK(recv(x, buf, 5, MSG_PEEK) == 5 && memcmp(buf, "hello", 5) == 0);
	CHECK(recv(x, buf, sizeof buf, 0) == 11);
	CHECK(recv(x, buf, sizeof buf, MSG_DONTWAIT) == -1 && errno == EAGAIN);

	/* A megabyte from a child, read to the end. */
	pid_t pid = fork();
	if (pid == 0) {
		static char big[65536];
		for (int i = 0; i < (int)sizeof big; i++)
			big[i] = (char)(i * 7);
		for (int i = 0; i < 16; i++)
			if (write(x, big, sizeof big) != sizeof big)
				_exit(1);
		_exit(0);
	}
	close(x);
	long total = 0, sum = 0;
	for (;;) {
		ssize_t r = read(c, buf, sizeof buf);
		if (r <= 0)
			break;
		for (ssize_t i = 0; i < r; i++)
			sum += (unsigned char)buf[i] ^ (unsigned char)(char)((total + i) * 7);
		total += r;
	}
	int st = 0;
	waitpid(pid, &st, 0);
	CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0);
	CHECK(total == 16 * 65536 && sum == 0);
	CHECK(read(c, buf, sizeof buf) == 0);
	CHECK(shutdown(c, SHUT_WR) == 0);
	CHECK(send(c, "x", 1, MSG_NOSIGNAL) == -1 && errno == EPIPE);
	close(c);

	/* Half close: the server still answers after the client's FIN. */
	c = socket(AF_INET, SOCK_STREAM, 0);
	CHECK(connect(c, (struct sockaddr *)&a, sizeof a) == 0);
	x = accept(s, NULL, NULL);
	CHECK(x >= 0);
	CHECK(write(c, "question", 8) == 8);
	CHECK(shutdown(c, SHUT_WR) == 0);
	CHECK(read(x, buf, sizeof buf) == 8);
	CHECK(read(x, buf, sizeof buf) == 0);
	CHECK(write(x, "answer", 6) == 6);
	close(x);
	CHECK(read(c, buf, sizeof buf) == 6 && memcmp(buf, "answer", 6) == 0);
	CHECK(read(c, buf, sizeof buf) == 0);
	close(c);

	/* Non-blocking connect. */
	c = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
	CHECK(connect(c, (struct sockaddr *)&a, sizeof a) == 0 || errno == EINPROGRESS);
	p = (struct pollfd){.fd = c, .events = POLLOUT};
	CHECK(poll(&p, 1, 2000) == 1 && (p.revents & POLLOUT));
	CHECK(opt(c, SOL_SOCKET, SO_ERROR) == 0);
	x = accept(s, NULL, NULL);
	CHECK(x >= 0);
	CHECK(recv(c, buf, sizeof buf, 0) == -1 && errno == EAGAIN);
	close(x);
	close(c);

	/* Nobody listening: refused. */
	close(s);
	usleep(100000);
	c = socket(AF_INET, SOCK_STREAM, 0);
	CHECK(connect(c, (struct sockaddr *)&a, sizeof a) == -1 && errno == ECONNREFUSED);
	close(c);
	CHECK(socket(AF_INET, SOCK_STREAM, IPPROTO_UDP) == -1 && errno == EPROTONOSUPPORT);
}

static void udp(void)
{
	char buf[64];
	puts("# udp");
	int u1 = socket(AF_INET, SOCK_DGRAM, 0);
	int u2 = socket(AF_INET, SOCK_DGRAM, 0);
	CHECK(u1 >= 0 && u2 >= 0);
	CHECK(opt(u1, SOL_SOCKET, SO_TYPE) == SOCK_DGRAM);
	struct sockaddr_in a = loopback(0);
	CHECK(bind(u1, (struct sockaddr *)&a, sizeof a) == 0);
	int port = port_of(u1, 0);
	a = loopback(port);
	CHECK(sendto(u2, "ping", 4, 0, (struct sockaddr *)&a, sizeof a) == 4);
	CHECK(port_of(u2, 0) > 0);
	struct sockaddr_in from;
	socklen_t flen = sizeof from;
	CHECK(recvfrom(u1, buf, sizeof buf, 0, (struct sockaddr *)&from, &flen) == 4);
	CHECK(memcmp(buf, "ping", 4) == 0);
	CHECK(ntohs(from.sin_port) == port_of(u2, 0));
	CHECK(from.sin_addr.s_addr == htonl(INADDR_LOOPBACK));
	CHECK(recv(u1, buf, sizeof buf, MSG_DONTWAIT) == -1 && errno == EAGAIN);
	CHECK(connect(u2, (struct sockaddr *)&a, sizeof a) == 0);
	CHECK(port_of(u2, 1) == port);
	CHECK(send(u2, "abcdef", 6, 0) == 6);
	CHECK(send(u2, "second", 6, 0) == 6);
	struct pollfd p = {.fd = u1, .events = POLLIN};
	CHECK(poll(&p, 1, 2000) == 1);
	CHECK(recv(u1, buf, 3, 0) == 3 && memcmp(buf, "abc", 3) == 0);
	CHECK(recv(u1, buf, sizeof buf, 0) == 6 && memcmp(buf, "second", 6) == 0);
	close(u1);
	close(u2);
}

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	signal(SIGPIPE, SIG_IGN);
	tcp();
	udp();
	printf("%s\n", failures ? "SOME CHECKS FAILED" : "all checks passed");
	return failures != 0;
}
