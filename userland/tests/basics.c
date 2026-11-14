/*
 * Phase 2 conformance test. `cargo xtask test` runs it on Linux and on
 * SegOS; both must print exactly basics.expected and exit with 0.
 * Keep the output deterministic: no pids, times or addresses.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <time.h>
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

static int64_t ns(clockid_t clock)
{
	struct timespec t;
	clock_gettime(clock, &t);
	return (int64_t)t.tv_sec * 1000000000 + t.tv_nsec;
}

static void args(int argc, char **argv, char **envp)
{
	printf("# arguments and the auxiliary vector\n");
	CHECK(argc >= 1);
	CHECK(argv[argc] == NULL);
	CHECK(envp != NULL);
	CHECK(getauxval(AT_PAGESZ) == 4096);
	CHECK(getauxval(AT_RANDOM) != 0);
	CHECK(getauxval(AT_PHDR) != 0);
	CHECK(getauxval(AT_ENTRY) != 0);
}

static void ids(void)
{
	printf("# identity\n");
	CHECK(getpid() > 0);
	CHECK(syscall(SYS_gettid) == getpid());
	CHECK(getppid() >= 0);
	CHECK(getuid() == geteuid());
	CHECK(getgid() == getegid());
	struct utsname u;
	CHECK(uname(&u) == 0);
	CHECK(strcmp(u.sysname, "Linux") == 0);
	CHECK(strcmp(u.machine, "x86_64") == 0);
}

static void output(void)
{
	printf("# writev\n");
	fflush(stdout);
	struct iovec iov[3] = {
		{ "ok   writev ", 12 }, { "of three ", 9 }, { "pieces\n", 7 },
	};
	CHECK(writev(1, iov, 3) == 28);
	CHECK(write(1, (void *)1, 1) == -1 && errno == EFAULT);
	CHECK(write(1234, "x", 1) == -1 && errno == EBADF);
}

static void memory(void)
{
	printf("# brk, mmap, munmap, mprotect, malloc\n");
	/* musl's sbrk() only answers sbrk(0); use the system call. */
	char *top = (char *)syscall(SYS_brk, 0);
	CHECK(top != NULL);
	CHECK((char *)syscall(SYS_brk, top + 4 * 4096) == top + 4 * 4096);
	memset(top, 0x5e, 4 * 4096);
	CHECK(top[4 * 4096 - 1] == 0x5e);
	CHECK((char *)syscall(SYS_brk, top) == top);
	CHECK((char *)syscall(SYS_brk, 0) == top);
	CHECK((char *)syscall(SYS_brk, 1) == top);

	size_t len = 64 * 1024;
	unsigned char *p = mmap(NULL, len, PROT_READ | PROT_WRITE,
				MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	CHECK(p != MAP_FAILED);
	CHECK(p[0] == 0 && p[len - 1] == 0);
	for (size_t i = 0; i < len; i++)
		p[i] = (unsigned char)i;
	int good = 1;
	for (size_t i = 0; i < len; i++)
		good &= p[i] == (unsigned char)i;
	CHECK(good);
	CHECK(munmap(p, len) == 0);
	CHECK(munmap(p, len) == 0);

	char *r = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	CHECK(r != MAP_FAILED);
	CHECK(mprotect(r, 4096, PROT_READ | PROT_WRITE) == 0);
	r[100] = 'x';
	CHECK(r[100] == 'x');
	CHECK(munmap(r, 4096) == 0);

	char *want = (char *)0x10000000;
	char *f = mmap(want, 8192, PROT_READ | PROT_WRITE,
		       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
	CHECK(f == want);
	f[8191] = 1;
	CHECK(munmap(f, 8192) == 0);
	CHECK(mmap(NULL, 0, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) ==
		      MAP_FAILED && errno == EINVAL);

	char *big = malloc(4 << 20);
	CHECK(big != NULL);
	memset(big, 1, 4 << 20);
	free(big);
	void *small[1000];
	for (int i = 0; i < 1000; i++)
		small[i] = malloc(16 + i);
	good = 1;
	for (int i = 0; i < 1000; i++)
		good &= small[i] != NULL;
	CHECK(good);
	for (int i = 0; i < 1000; i++)
		free(small[i]);
}

static void files(void)
{
	printf("# files\n");
	const char *name = "segos-basics.tmp";
	char buf[64] = { 0 };
	int fd = open(name, O_CREAT | O_TRUNC | O_RDWR, 0644);
	CHECK(fd >= 3);
	CHECK(write(fd, "hello, file\n", 12) == 12);
	CHECK(lseek(fd, 0, SEEK_CUR) == 12);
	CHECK(lseek(fd, 0, SEEK_SET) == 0);
	CHECK(read(fd, buf, sizeof buf) == 12);
	CHECK(memcmp(buf, "hello, file\n", 12) == 0);
	CHECK(read(fd, buf, sizeof buf) == 0);
	CHECK(pread(fd, buf, 4, 7) == 4 && memcmp(buf, "file", 4) == 0);
	CHECK(lseek(fd, 0, SEEK_END) == 12);
	CHECK(lseek(fd, -1, SEEK_SET) == -1 && errno == EINVAL);
	struct stat st;
	CHECK(fstat(fd, &st) == 0);
	CHECK(S_ISREG(st.st_mode) && st.st_size == 12);
	CHECK((st.st_mode & 0777) == 0644 || (st.st_mode & 0777) == 0600 ||
	      (st.st_mode & 0777) == 0640);
	CHECK(pwrite(fd, "F", 1, 7) == 1);
	CHECK(pread(fd, buf, 12, 0) == 12 &&
	      memcmp(buf, "hello, File\n", 12) == 0);
	CHECK(ftruncate(fd, 5) == 0);
	CHECK(fstat(fd, &st) == 0 && st.st_size == 5);
	int fd2 = dup(fd);
	CHECK(fd2 > fd);
	CHECK(dup2(fd, 20) == 20);
	CHECK(lseek(20, 0, SEEK_SET) == 0 && lseek(fd2, 0, SEEK_CUR) == 0);
	CHECK(close(20) == 0 && close(fd2) == 0);
	CHECK(close(fd) == 0);
	CHECK(close(fd) == -1 && errno == EBADF);
	CHECK(stat(name, &st) == 0 && st.st_size == 5);
	CHECK(access(name, F_OK) == 0);
	CHECK(open(name, O_CREAT | O_EXCL | O_WRONLY, 0644) == -1 &&
	      errno == EEXIST);
	CHECK(unlink(name) == 0);
	CHECK(open(name, O_RDONLY) == -1 && errno == ENOENT);
	CHECK(stat("no/such/dir/file", &st) == -1 && errno == ENOENT);

	CHECK(mkdir("segos-basics.dir", 0755) == 0);
	CHECK(mkdir("segos-basics.dir", 0755) == -1 && errno == EEXIST);
	CHECK(stat("segos-basics.dir", &st) == 0 && S_ISDIR(st.st_mode));
	fd = open("segos-basics.dir/inner", O_CREAT | O_WRONLY, 0600);
	CHECK(fd >= 0 && close(fd) == 0);
	CHECK(rmdir("segos-basics.dir") == -1 && errno == ENOTEMPTY);
	CHECK(unlink("segos-basics.dir/./inner") == 0);
	CHECK(rmdir("segos-basics.dir") == 0);
	CHECK(open("segos-basics.dir/inner", O_RDONLY) == -1 &&
	      errno == ENOENT);

	char cwd[256];
	CHECK(getcwd(cwd, sizeof cwd) != NULL && cwd[0] == '/');
	fd = open("/dev/null", O_RDWR);
	CHECK(fd >= 0);
	CHECK(write(fd, "gone", 4) == 4 && read(fd, buf, 4) == 0);
	CHECK(close(fd) == 0);
}

static void time_and_random(void)
{
	printf("# time and randomness\n");
	int64_t a = ns(CLOCK_MONOTONIC);
	struct timespec d = { 0, 20 * 1000 * 1000 };
	CHECK(nanosleep(&d, NULL) == 0);
	int64_t b = ns(CLOCK_MONOTONIC);
	CHECK(b - a >= 20 * 1000 * 1000);
	CHECK(b - a < 2000LL * 1000 * 1000);
	CHECK(ns(CLOCK_REALTIME) / 1000000000 > 1700000000);
	CHECK(time(NULL) > 1700000000);
	unsigned char r1[16] = { 0 }, r2[16] = { 0 };
	CHECK(getrandom(r1, 16, 0) == 16 && getrandom(r2, 16, 0) == 16);
	CHECK(memcmp(r1, r2, 16) != 0);
	printf("ok   %.3f\n", 3.14159 * 2);
}

static void unknown(void)
{
	printf("# unknown system calls fail cleanly\n");
	CHECK(syscall(999) == -1 && errno == ENOSYS);
}

int main(int argc, char **argv, char **envp)
{
	args(argc, argv, envp);
	ids();
	output();
	memory();
	files();
	time_and_random();
	unknown();
	printf("%d failures\n", failures);
	return failures ? 1 : 0;
}
