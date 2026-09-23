// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * kpmctl — load/control KernelPatch Modules (KPM) against the LKM or kpimg.
 *
 * The KP supercall channel rides on syscall 45 (__NR3264_truncate):
 *   syscall(45, key, ver_and_cmd, a1, a2, a3, a4)
 *
 * In LKM mode the kernel authenticates by caller uid only (manager uid or
 * su-allowlist uid); the key is NOT verified, and the convention for
 * su-allowed uids (shell 2000 / root 0) is to pass "su". For kpimg with a
 * preset superkey, pass -k <superkey>.
 *
 * Build (NDK clang, arm64, static so it runs from /data/local/tmp with no deps):
 *   $CC -static -O2 -Wall -o kpmctl kpmctl.c
 * where $CC is aarch64-linux-android<api>-clang from the NDK toolchains/llvm.
 *
 * Usage:
 *   kpmctl [-k key] hello                  test supercall (expect 0x11581158)
 *   kpmctl [-k key] load <kpm_path> [args] load a .kpm file
 *   kpmctl [-k key] unload <name>          unload module by name
 *   kpmctl [-k key] nums                   number of loaded modules
 *   kpmctl [-k key] list                   list loaded module names
 *   kpmctl [-k key] info <name>            show a module's info
 *   kpmctl [-k key] control <name> <args>  send a control message
 *
 * Caller must run as a uid the kernel authorizes (manager uid, or an su-allowed
 * uid such as 0/2000); otherwise the supercall falls through to real truncate()
 * and returns -ENOSYS or a truncate error.
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>

#define __NR_supercall 45 /* __NR3264_truncate, reused as the KP supercall channel */

/* Command IDs mirror kernel/patch/include/uapi/scdefs.h. */
#define SUPERCALL_HELLO        0x1000L
#define SUPERCALL_KPM_LOAD     0x1020L
#define SUPERCALL_KPM_UNLOAD   0x1021L
#define SUPERCALL_KPM_CONTROL  0x1022L
#define SUPERCALL_KPM_NUMS     0x1030L
#define SUPERCALL_KPM_LIST     0x1031L
#define SUPERCALL_KPM_INFO     0x1032L

#define SUPERCALL_HELLO_MAGIC  0x11581158L

/* ver_and_cmd mirrors user/supercall.h: (version<<32)|(0x1158<<16)|(cmd&0xFFFF).
 * The LKM keeps only the low 16 bits (cmd); kpimg verifies the rest. We emit the
 * full encoding so the same binary works against both. */
static long ver_and_cmd(long cmd)
{
	long version_code = 0x0A05L; /* 0.10.5 */
	return (version_code << 32) | (0x1158L << 16) | (cmd & 0xFFFF);
}

/* "su" is the user-space convention for su-allowed uids; the LKM does not
 * verify the key. Override with -k for kpimg + preset superkey. */
static const char *g_key = "su";

static long kp_sc(long cmd, long a1, long a2, long a3, long a4)
{
	return syscall(__NR_supercall, g_key, ver_and_cmd(cmd), a1, a2, a3, a4);
}

static void usage(FILE *out)
{
	fprintf(out,
		"usage: kpmctl [-k key] <command> [args]\n"
		"  -k key                    superkey (default \"su\"; LKM ignores it)\n"
		"  hello                     test supercall, expect magic 0x11581158\n"
		"  load <path> [args]        load a .kpm file\n"
		"  unload <name>             unload module by name\n"
		"  nums                      number of loaded modules\n"
		"  list                      list loaded module names\n"
		"  info <name>               show module info\n"
		"  control <name> <args>     send a control message\n");
}

static int fail(const char *what, long rc)
{
	if (rc < 0)
		fprintf(stderr, "%s failed: rc=%ld errno=%d (%s)\n", what, rc, errno,
			strerror(errno));
	else
		fprintf(stderr, "%s failed: rc=%ld\n", what, rc);
	return 1;
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		usage(stderr);
		return 1;
	}

	int ai = 1;
	if (strcmp(argv[ai], "-k") == 0) {
		if (ai + 1 >= argc) {
			fprintf(stderr, "-k requires a key\n");
			return 1;
		}
		g_key = argv[ai + 1];
		ai += 2;
		if (ai >= argc) {
			usage(stderr);
			return 1;
		}
	}

	const char *sub = argv[ai++];

	if (!strcmp(sub, "hello")) {
		long rc = kp_sc(SUPERCALL_HELLO, 0, 0, 0, 0);
		if (rc == SUPERCALL_HELLO_MAGIC) {
			printf("hello ok (magic=0x%lx)\n", rc);
			return 0;
		}
		return fail("hello", rc);
	}

	if (!strcmp(sub, "load")) {
		if (ai >= argc) {
			fprintf(stderr, "load: missing <path>\n");
			return 1;
		}
		const char *path = argv[ai++];
		const char *args = (ai < argc) ? argv[ai++] : NULL;
		long rc = kp_sc(SUPERCALL_KPM_LOAD, (long)path, (long)args, 0, 0);
		if (rc < 0)
			return fail("load", rc);
		printf("load ok: rc=%ld\n", rc);
		return 0;
	}

	if (!strcmp(sub, "unload")) {
		if (ai >= argc) {
			fprintf(stderr, "unload: missing <name>\n");
			return 1;
		}
		long rc = kp_sc(SUPERCALL_KPM_UNLOAD, (long)argv[ai++], 0, 0, 0);
		if (rc < 0)
			return fail("unload", rc);
		printf("unload ok: rc=%ld\n", rc);
		return 0;
	}

	if (!strcmp(sub, "nums")) {
		long rc = kp_sc(SUPERCALL_KPM_NUMS, 0, 0, 0, 0);
		if (rc < 0)
			return fail("nums", rc);
		printf("%ld\n", rc);
		return 0;
	}

	if (!strcmp(sub, "list")) {
		char buf[4096];
		memset(buf, 0, sizeof(buf));
		long rc = kp_sc(SUPERCALL_KPM_LIST, (long)buf, sizeof(buf), 0, 0);
		if (rc < 0)
			return fail("list", rc);
		if (rc > 0)
			fwrite(buf, 1, rc, stdout);
		return 0;
	}

	if (!strcmp(sub, "info")) {
		if (ai >= argc) {
			fprintf(stderr, "info: missing <name>\n");
			return 1;
		}
		char buf[2048];
		memset(buf, 0, sizeof(buf));
		long rc = kp_sc(SUPERCALL_KPM_INFO, (long)argv[ai++], (long)buf,
				sizeof(buf), 0);
		if (rc < 0)
			return fail("info", rc);
		if (rc > 0)
			fwrite(buf, 1, rc, stdout);
		return 0;
	}

	if (!strcmp(sub, "control")) {
		if (ai + 1 >= argc) {
			fprintf(stderr, "control: needs <name> <args>\n");
			return 1;
		}
		char buf[1024];
		memset(buf, 0, sizeof(buf));
		long rc = kp_sc(SUPERCALL_KPM_CONTROL, (long)argv[ai],
				(long)argv[ai + 1], (long)buf, sizeof(buf));
		if (rc < 0)
			return fail("control", rc);
		printf("control ok: rc=%ld\n", rc);
		if (rc > 0)
			fwrite(buf, 1, rc, stdout);
		return 0;
	}

	fprintf(stderr, "unknown command: %s\n", sub);
	usage(stderr);
	return 1;
}
