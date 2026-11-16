/*
 * Phase 8 conformance test: what browser sandboxes (Firefox's, Chromium's)
 * use: seccomp-bpf filters (ALLOW, ERRNO, TRAP with a SIGSYS handler,
 * KILL), stacked and inherited filters, TSYNC, strict mode, and
 * no_new_privs. `cargo xtask test` runs it on Linux and on SegOS; both
 * must print exactly sandbox.expected and exit with 0.
 *
 * musl has no <linux/filter.h> or <linux/seccomp.h>: the few structures
 * and constants are spelled out here.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <ucontext.h>
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

/* <linux/filter.h>, <linux/seccomp.h>, <linux/audit.h> */
struct sock_filter {
	uint16_t code;
	uint8_t jt, jf;
	uint32_t k;
};
struct sock_fprog {
	unsigned short len;
	struct sock_filter *filter;
};
struct seccomp_data {
	int nr;
	uint32_t arch;
	uint64_t instruction_pointer;
	uint64_t args[6];
};
#define BPF_LD 0x00
#define BPF_ALU 0x04
#define BPF_JMP 0x05
#define BPF_RET 0x06
#define BPF_ST 0x02
#define BPF_W 0x00
#define BPF_ABS 0x20
#define BPF_MEM 0x60
#define BPF_AND 0x50
#define BPF_JEQ 0x10
#define BPF_JSET 0x40
#define BPF_K 0x00
#define BPF_STMT(code, k) {(uint16_t)(code), 0, 0, (k)}
#define BPF_JUMP(code, k, jt, jf) {(uint16_t)(code), (jt), (jf), (k)}
#define SECCOMP_MODE_STRICT 1
#define SECCOMP_MODE_FILTER 2
#define SECCOMP_SET_MODE_FILTER 1
#define SECCOMP_GET_ACTION_AVAIL 2
#define SECCOMP_FILTER_FLAG_TSYNC 1
#define SECCOMP_RET_KILL_PROCESS 0x80000000U
#define SECCOMP_RET_TRAP 0x00030000U
#define SECCOMP_RET_ERRNO 0x00050000U
#define SECCOMP_RET_ALLOW 0x7fff0000U
#define AUDIT_ARCH_X86_64 0xc000003eU
#define SYS_SECCOMP 1
#ifndef PR_SET_NO_NEW_PRIVS
#define PR_SET_NO_NEW_PRIVS 38
#define PR_GET_NO_NEW_PRIVS 39
#endif

#define LOAD_NR BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr))
#define LOAD_ARCH BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch))
#define LOAD_ARG0 BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args))
/* If the call is `nr`, return `ret`. */
#define ON(nr, ret) BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (nr), 0, 1), BPF_STMT(BPF_RET | BPF_K, (ret))
#define ALLOW BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)

static int install(struct sock_filter *f, unsigned short n, unsigned flags)
{
	struct sock_fprog prog = {n, f};
	return syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, flags, &prog);
}

static int install_prctl(struct sock_filter *f, unsigned short n)
{
	struct sock_fprog prog = {n, f};
	return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0);
}

/* Runs `fn` in a child; returns its wait status. */
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

/* --- probes and checks ---------------------------------------------- */

static void probes(void)
{
	section("probes");
	CHECK(prctl(PR_GET_SECCOMP) == 0);
	/* Firefox's test for seccomp-bpf: a NULL program is EFAULT. */
	CHECK(prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, NULL, 0, 0) == -1 &&
	      errno == EFAULT);
	CHECK(syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER,
		      SECCOMP_FILTER_FLAG_TSYNC, NULL) == -1 &&
	      errno == EFAULT);
	uint32_t action = SECCOMP_RET_TRAP;
	CHECK(syscall(SYS_seccomp, SECCOMP_GET_ACTION_AVAIL, 0, &action) == 0);
	action = 0x12340000;
	CHECK(syscall(SYS_seccomp, SECCOMP_GET_ACTION_AVAIL, 0, &action) == -1 &&
	      errno == EOPNOTSUPP);
	CHECK(prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 0);
}

static void bad_programs(void)
{
	section("bad programs");
	CHECK(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);
	CHECK(prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1);
	struct sock_filter jump_out[] = {
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 1, 5, 0),
		ALLOW,
	};
	CHECK(install(jump_out, 2, 0) == -1 && errno == EINVAL);
	struct sock_filter no_return[] = {LOAD_NR};
	CHECK(install(no_return, 1, 0) == -1 && errno == EINVAL);
	struct sock_filter past_data[] = {
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 64),
		ALLOW,
	};
	CHECK(install(past_data, 2, 0) == -1 && errno == EINVAL);
	struct sock_filter misaligned[] = {
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 2),
		ALLOW,
	};
	CHECK(install(misaligned, 2, 0) == -1 && errno == EINVAL);
	CHECK(install(misaligned, 0, 0) == -1 && errno == EINVAL);
	CHECK(prctl(PR_GET_SECCOMP) == 0);
}

/* --- filters --------------------------------------------------------- */

static volatile int traps;
static volatile long trapped_nr, trapped_arch, trapped_data, trapped_rax;

static void on_sigsys(int sig, siginfo_t *si, void *uc_)
{
	ucontext_t *uc = uc_;
	(void)sig;
	traps++;
	trapped_nr = si->si_code == SYS_SECCOMP ? si->si_syscall : -1;
	trapped_arch = si->si_arch;
	trapped_data = si->si_errno;
	trapped_rax = uc->uc_mcontext.gregs[REG_RAX];
	/* The call "returns" what the handler puts in RAX. */
	uc->uc_mcontext.gregs[REG_RAX] = 4242;
}

static void *thread_getppid(void *arg)
{
	(void)arg;
	long r = syscall(SYS_getppid);
	return (void *)(r == -1 ? (long)errno : 0L);
}

static void filtered(void)
{
	CHECK(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);
	struct sock_filter first[] = {
		LOAD_ARCH,
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
		LOAD_NR,
		ON(SYS_getppid, SECCOMP_RET_ERRNO | 42),
		ON(SYS_getsid, SECCOMP_RET_TRAP | 0x55),
		ON(SYS_getuid, SECCOMP_RET_KILL_PROCESS),
		/* getpriority(which, who): which with any of 0x100 set ->
		 * ERRNO 9; which & 0xff == 0x7f (via the scratch memory) ->
		 * ERRNO 7. */
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_getpriority, 0, 8),
		LOAD_ARG0,
		BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, 0x100, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | 9),
		BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0xff),
		BPF_STMT(BPF_ST, 3),
		BPF_STMT(BPF_LD | BPF_MEM, 3),
		ON(0x7f, SECCOMP_RET_ERRNO | 7),
		ALLOW,
	};
	CHECK(install_prctl(first, sizeof first / sizeof first[0]) == 0);
	CHECK(prctl(PR_GET_SECCOMP) == SECCOMP_MODE_FILTER);
	CHECK(syscall(SYS_getppid) == -1 && errno == 42);
	CHECK(syscall(SYS_getpid) > 0);
	CHECK(syscall(SYS_getpriority, 0x1ff, 0) == -1 && errno == 9);
	CHECK(syscall(SYS_getpriority, 0x7f, 0) == -1 && errno == 7);
	CHECK(syscall(SYS_getpriority, 0, 0) >= 0);

	struct sigaction sa;
	memset(&sa, 0, sizeof sa);
	sa.sa_sigaction = on_sigsys;
	sa.sa_flags = SA_SIGINFO;
	sigaction(SIGSYS, &sa, NULL);
	long r = syscall(SYS_getsid);
	CHECK(traps == 1 && r == 4242);
	CHECK(trapped_nr == SYS_getsid && trapped_arch == (long)AUDIT_ARCH_X86_64);
	CHECK(trapped_data == 0x55 && trapped_rax == SYS_getsid);

	/* A second filter: both say ERRNO; the newer one's wins. */
	struct sock_filter second[] = {
		LOAD_NR,
		ON(SYS_getppid, SECCOMP_RET_ERRNO | 1),
		ON(SYS_getpgrp, SECCOMP_RET_ERRNO | 3),
		ALLOW,
	};
	CHECK(install(second, sizeof second / sizeof second[0], 0) == 0);
	CHECK(syscall(SYS_getppid) == -1 && errno == 1);
	CHECK(syscall(SYS_getpgrp) == -1 && errno == 3);
	/* TRAP beats the newer filter's ALLOW. */
	CHECK(syscall(SYS_getsid) == 4242 && traps == 2);

	/* Threads inherit the filters; children of fork too. */
	pthread_t th;
	void *res;
	pthread_create(&th, NULL, thread_getppid, NULL);
	pthread_join(th, &res);
	CHECK((long)res == 1);
	pid_t pid = fork();
	if (pid == 0)
		_exit(syscall(SYS_getpgrp) == -1 && errno == 3 ? 0 : 1);
	int status = 0;
	waitpid(pid, &status, 0);
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);

	/* KILL_PROCESS: the process ends by SIGSYS. */
	fflush(stdout);
	pid = fork();
	if (pid == 0) {
		syscall(SYS_getuid);
		_exit(0);
	}
	waitpid(pid, &status, 0);
	CHECK(WIFSIGNALED(status) && WTERMSIG(status) == SIGSYS);
}

static volatile int go, done;
static long seen_in_thread;

static void *waiting_thread(void *arg)
{
	(void)arg;
	while (!go)
		usleep(1000);
	seen_in_thread = syscall(SYS_getpgrp) == -1 ? errno : 0;
	done = 1;
	return NULL;
}

static void tsync(void)
{
	CHECK(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);
	pthread_t th;
	pthread_create(&th, NULL, waiting_thread, NULL);
	struct sock_filter f[] = {
		LOAD_NR,
		ON(SYS_getpgrp, SECCOMP_RET_ERRNO | 5),
		ALLOW,
	};
	CHECK(install(f, sizeof f / sizeof f[0], SECCOMP_FILTER_FLAG_TSYNC) == 0);
	go = 1;
	pthread_join(th, NULL);
	CHECK(done && seen_in_thread == 5);
}

static void strict(void)
{
	static const char msg[] = "ok   write in strict mode\n";
	fflush(stdout);
	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT) != 0)
		_exit(3);
	write(1, msg, sizeof msg - 1);
	syscall(SYS_getpid); /* SIGKILL */
	syscall(SYS_exit, 4);
}

static void modes(void)
{
	section("filters");
	int status = in_child(filtered);
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	section("tsync");
	status = in_child(tsync);
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	section("strict");
	status = in_child(strict);
	CHECK(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
	/* None of it reached this process. */
	CHECK(prctl(PR_GET_SECCOMP) == 0 && syscall(SYS_getppid) != -1);
}

int main(void)
{
	setvbuf(stdout, NULL, _IOLBF, 0);
	probes();
	modes();
	bad_programs();
	printf("%s\n", failures ? "FAILED" : "PASSED");
	return failures != 0;
}
