/*
 * Phase 4 conformance test: shared mappings and the page cache.
 * `cargo xtask test` runs it on Linux and on SegOS; both must print
 * exactly mapping.expected and exit with 0. Deterministic output only.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/stat.h>
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

static const char *name = "segos-mapping.tmp";

static void shared_file(void)
{
	printf("# shared file mapping\n");
	int fd = open(name, O_CREAT | O_TRUNC | O_RDWR, 0644);
	CHECK(fd >= 3);
	CHECK(ftruncate(fd, 8192) == 0);
	char *p = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	CHECK(p != MAP_FAILED);
	/* A store through the mapping is seen by read(). */
	memcpy(p + 4090, "across a page", 13);
	char buf[32] = { 0 };
	CHECK(pread(fd, buf, 13, 4090) == 13);
	CHECK(memcmp(buf, "across a page", 13) == 0);
	/* A write() is seen through the mapping. */
	CHECK(pwrite(fd, "WRITTEN", 7, 100) == 7);
	CHECK(memcmp(p + 100, "WRITTEN", 7) == 0);
	/* A second mapping of the same file shares the pages. */
	char *q = mmap(NULL, 4096, PROT_READ, MAP_SHARED, fd, 4096);
	CHECK(q != MAP_FAILED);
	p[4096 + 7] = 'Z';
	CHECK(q[7] == 'Z');
	CHECK(msync(p, 8192, MS_SYNC) == 0);
	CHECK(munmap(q, 4096) == 0);
	CHECK(munmap(p, 8192) == 0);
	/* After unmapping, the file keeps what was stored. */
	memset(buf, 0, sizeof buf);
	CHECK(pread(fd, buf, 13, 4090) == 13);
	CHECK(memcmp(buf, "across a page", 13) == 0);
	CHECK(pread(fd, buf, 1, 4096 + 7) == 1 && buf[0] == 'Z');
	close(fd);
	/* And a fresh open sees it too. */
	fd = open(name, O_RDONLY);
	struct stat st;
	CHECK(fstat(fd, &st) == 0 && st.st_size == 8192);
	CHECK(pread(fd, buf, 7, 100) == 7 && memcmp(buf, "WRITTEN", 7) == 0);
	close(fd);
}

static void shared_fork(void)
{
	printf("# shared across fork\n");
	int *anon = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	CHECK(anon != MAP_FAILED);
	int *priv = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	CHECK(priv != MAP_FAILED);
	int fd = open(name, O_RDWR);
	char *file = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	CHECK(file != MAP_FAILED);
	anon[0] = 1;
	priv[0] = 1;
	pid_t child = fork();
	if (child == 0) {
		anon[0] = 42;
		priv[0] = 42;
		file[0] = 'C';
		_exit(0);
	}
	int status = -1;
	CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status));
	CHECK(anon[0] == 42); /* the child's store is seen */
	CHECK(priv[0] == 1);  /* a private mapping was copied */
	CHECK(file[0] == 'C');
	munmap(file, 4096);
	char c = 0;
	CHECK(pread(fd, &c, 1, 0) == 1 && c == 'C');
	close(fd);
	munmap(anon, 4096);
	munmap(priv, 4096);
}

static void remap(void)
{
	printf("# mremap (a growing wl_shm pool)\n");
	int fd = memfd_create("pool", MFD_CLOEXEC);
	CHECK(fd >= 3);
	CHECK(fallocate(fd, 0, 0, 4096) == 0);
	char *server = mmap(NULL, 4096, PROT_READ, MAP_SHARED, fd, 0);
	CHECK(server != MAP_FAILED);
	/* The client grows the pool and draws into the new part... */
	CHECK(fallocate(fd, 0, 0, 3 * 4096) == 0);
	struct stat st;
	CHECK(fstat(fd, &st) == 0 && st.st_size == 3 * 4096);
	char *client = mmap(NULL, 3 * 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	CHECK(client != MAP_FAILED);
	client[0] = 'A';
	client[2 * 4096 + 5] = 'B';
	/* ...and the server's grown mapping shows it. */
	char *grown = mremap(server, 4096, 3 * 4096, MREMAP_MAYMOVE);
	CHECK(grown != MAP_FAILED);
	CHECK(grown[0] == 'A' && grown[2 * 4096 + 5] == 'B');
	client[2 * 4096 + 6] = 'C';
	CHECK(grown[2 * 4096 + 6] == 'C');
	CHECK(mremap(grown, 3 * 4096, 4096, 0) == grown);
	CHECK(grown[0] == 'A');
	munmap(grown, 4096);
	munmap(client, 3 * 4096);
	close(fd);
	/* Private anonymous memory keeps its contents when it moves. */
	char *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	CHECK(p != MAP_FAILED);
	p[100] = 42;
	char *q = mremap(p, 4096, 1 << 20, MREMAP_MAYMOVE);
	CHECK(q != MAP_FAILED);
	CHECK(q[100] == 42 && q[(1 << 20) - 1] == 0);
	CHECK(munmap(q, 1 << 20) == 0);
}

static void locks(void)
{
	printf("# flock\n");
	int a = open(name, O_RDWR);
	int b = open(name, O_RDWR);
	CHECK(flock(a, LOCK_EX | LOCK_NB) == 0);
	CHECK(flock(b, LOCK_EX | LOCK_NB) == -1 && errno == EWOULDBLOCK);
	CHECK(flock(b, LOCK_SH | LOCK_NB) == -1 && errno == EWOULDBLOCK);
	/* The lock belongs to the open file, which a dup shares. */
	int c = dup(a);
	close(a);
	CHECK(flock(b, LOCK_SH | LOCK_NB) == -1 && errno == EWOULDBLOCK);
	close(c);
	CHECK(flock(b, LOCK_SH | LOCK_NB) == 0);
	int d = open(name, O_RDONLY);
	CHECK(flock(d, LOCK_SH | LOCK_NB) == 0);
	CHECK(flock(d, LOCK_EX | LOCK_NB) == -1 && errno == EWOULDBLOCK);
	CHECK(flock(b, LOCK_UN) == 0);
	CHECK(flock(d, LOCK_EX | LOCK_NB) == 0);
	close(b);
	close(d);
}

static void errors(void)
{
	printf("# errors\n");
	int fd = open(name, O_RDONLY);
	CHECK(mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0) == MAP_FAILED &&
	      errno == EACCES);
	/* A private writable mapping of a read-only file is fine. */
	char *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	CHECK(p != MAP_FAILED);
	p[0] = 'P';
	char c = 0;
	CHECK(pread(fd, &c, 1, 0) == 1 && c == 'C'); /* the file is unchanged */
	munmap(p, 4096);
	close(fd);
	CHECK(unlink(name) == 0);
}

int main(void)
{
	CHECK(chdir("/tmp") == 0);
	shared_file();
	shared_fork();
	remap();
	locks();
	errors();
	printf("%s\n", failures ? "FAILED" : "PASSED");
	return failures != 0;
}
