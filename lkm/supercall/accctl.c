// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 *
 * The ko is compiled against a fixed KMI, so struct cred fields are directly
 * addressable (KP's kpimg needs runtime cred_offset instead). Full root =
 * all capabilities + uid/gid switch via a freshly prepared cred. The SELinux
 * translabel helper is resolved at runtime like KP does.
 */
#include "accctl.h"

#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <scdefs.h>

#include "../include/kp_lkm.h"
#include "../infra/symbol_resolver.h"
#include "../infra/kfuncs.h"

/* selinux_blob_sizes is a global; resolve via kallsyms. cred->security is a
 * pointer to the LSM cred blob; the selinux part lives at +lbs_cred. */
struct kp_lsm_blob_sizes {
	int lbs_cred;
	int lbs_file;
	int lbs_inode;
	int lbs_superblock;
	int lbs_ipc;
	int lbs_msg_msg;
	int lbs_task;
};

static struct kp_lsm_blob_sizes *kp_selinux_blob_sizes;

/* find_get_task_by_vpid is not exported to modules; resolved by name at
 * kp_accctl_init and only called through this pointer. */
typedef struct task_struct *(*kp_find_get_task_by_vpid_t)(pid_t nr);
static kp_find_get_task_by_vpid_t kp_find_get_task_by_vpid;

/* task_security_struct { osid, sid, ... } — RANDSTRUCT is off, so sid is the
 * second u32 (offset 4). */
struct kp_task_sec {
	u32 osid;
	u32 sid;
};

int kp_accctl_init(void)
{
	kp_find_get_task_by_vpid = (kp_find_get_task_by_vpid_t)kp_resolve_symbol("find_get_task_by_vpid");
	if (!kp_find_get_task_by_vpid)
		logkw("failed to resolve find_get_task_by_vpid; task_su disabled\n");

	kp_selinux_blob_sizes = (struct kp_lsm_blob_sizes *)kp_resolve_symbol("selinux_blob_sizes");
	if (!kp_selinux_blob_sizes) {
		logke("failed to resolve selinux_blob_sizes; selinux translabel disabled\n");
		return 0;
	}
	logki("selinux blob sizes: lbs_cred=%d\n", kp_selinux_blob_sizes->lbs_cred);
	/* Probe and cache the first usable SELinux domain now, so the su allowlist
	 * and kp_commit_su see a stable answer without re-probing on every exec. */
	kp_get_available_sctx();
	return 0;
}

/* LKM mode ships no sepolicy patch, so u:r:kp:s0 is absent; on non-Magisk
 * devices u:r:magisk:s0 is absent too. Probe both and cache the first that
 * security_secctx_to_secid can resolve. Returns NULL if neither exists, in
 * which case kp_commit_su grants uid 0 + full caps on the caller's current
 * domain (no translabel). u:r:kernel:s0 is deliberately excluded: it cannot
 * connect sockets or run ART, so keeping the caller's own domain is better. */
const char *kp_get_available_sctx(void)
{
	static const char *const candidates[] = {
		ALL_ALLOW_SCONTEXT,	 /* u:r:kp:s0 */
		ALL_ALLOW_SCONTEXT_MAGISK, /* u:r:magisk:s0 */
	};
	static char cached[SUPERCALL_SCONTEXT_LEN];
	static bool probed;
	u32 sid = 0;
	int i;

	if (probed)
		return cached[0] ? cached : NULL;
	probed = true;

	if (!kp_selinux_blob_sizes)
		return NULL;

	for (i = 0; i < ARRAY_SIZE(candidates); i++) {
		if (!kp_security_secctx_to_secid(candidates[i], strlen(candidates[i]), &sid) && sid) {
			strscpy(cached, candidates[i], sizeof(cached));
			logki("available selinux domain: %s\n", cached);
			return cached;
		}
	}
	logkw("no usable selinux domain (kp/magisk both absent); root keeps caller domain\n");
	return NULL;
}

/* Translabel a freshly-prepared cred to the given SELinux context (5.15 has no
 * set_security_override_from_ctx; it was removed in GKI). Resolve the context
 * to a sid and write tsec->sid directly. */
static int kp_selinux_set_cred_context(struct cred *new, const char *sctx)
{
	struct kp_task_sec *tsec;
	u32 sid;
	int rc;

	if (!kp_selinux_blob_sizes || !sctx || !sctx[0])
		return -EINVAL;

	rc = kp_security_secctx_to_secid(sctx, strlen(sctx), &sid);
	if (rc || !sid) {
		logkw("secctx_to_secid(%s) failed: %d sid=%u\n", sctx, rc, sid);
		return rc ? rc : -EINVAL;
	}

	tsec = (struct kp_task_sec *)((char *)new->security + kp_selinux_blob_sizes->lbs_cred);
	tsec->sid = sid;
	return 0;
}

/* Fill every capability in a kernel_cap_t. */
static void fill_caps(struct cred *new)
{
	kernel_cap_t all = CAP_FULL_SET;
	new->cap_effective = all;
	new->cap_permitted = all;
	new->cap_inheritable = all;
	new->cap_bset = all;
	new->cap_ambient = all;
}

static void su_cred(struct cred *new, uid_t uid)
{
	fill_caps(new);
	new->uid = make_kuid(current_user_ns(), uid);
	new->euid = new->uid;
	new->fsuid = new->uid;
	new->suid = new->uid;
	new->gid = make_kgid(current_user_ns(), uid);
	new->egid = new->gid;
	new->fsgid = new->gid;
	new->sgid = new->gid;
}

/* no_sanitize("cfi") keeps indirect calls in this function from tripping
 * __cfi_check on traditional-CFI 5.15 kernels. */
__attribute__((no_sanitize("cfi")))
static int commit_common_su(uid_t to_uid, const char *sctx)
{
	struct cred *new = kp_prepare_creds();
	if (!new)
		return -ENOMEM;

	su_cred(new, to_uid);

	/* Translabel to sctx (e.g. u:r:magisk:s0 / u:r:kp:s0). Without this the
	 * granted process keeps its untrusted_app SELinux domain while running as
	 * uid 0 with all caps — Android blocks it and the app fails to open. If
	 * translabel fails, abort the creds so the caller falls back to another
	 * domain instead of committing an untranslabelled root. */
	if (sctx && sctx[0]) {
		int rc = kp_selinux_set_cred_context(new, sctx);
		if (rc) {
			logkw("selinux set context(%s) failed: %d\n", sctx, rc);
			kp_abort_creds(new);
			return rc;
		}
	}

	kp_commit_creds(new);
	return 0;
}

__attribute__((no_sanitize("cfi")))
int kp_commit_su(uid_t to_uid, const char *sctx)
{
	int rc;

	/* Disable seccomp on the caller, matching KP's commit_common_su. */
	current_thread_info()->flags &= ~_TIF_SECCOMP;

	/* Empty sctx: pick the first probed SELinux domain (u:r:kp:s0 or
	 * u:r:magisk:s0). If neither exists — the common LKM case on a non-Magisk
	 * device, since LKM mode ships no sepolicy patch — grant uid 0 + full caps
	 * on the caller's current domain. prepare_kernel_cred(NULL) is deprecated
	 * since 6.2 (it WARNs and returns NULL on 6.12), so the fallback builds
	 * the root cred from prepare_creds() + su_cred() instead. */
	if (!sctx || !sctx[0]) {
		const char *avail = kp_get_available_sctx();
		if (avail && kp_selinux_blob_sizes) {
			rc = commit_common_su(to_uid, avail);
			if (!rc) {
				logki("commit_su: to_uid=%u domain %s\n", to_uid, avail);
				return 0;
			}
			logkw("domain %s translabel failed (%d), cred fallback\n", avail, rc);
		}
		struct cred *new = kp_prepare_creds();
		if (!new)
			return -ENOMEM;
		su_cred(new, to_uid);
		kp_commit_creds(new);
		logki("commit_su: to_uid=%u cred fallback (no selinux domain)\n", to_uid);
		return 0;
	}

	/* Explicit sctx: try the translabel, fall back to a uid-0 cred on the
	 * caller's current domain if it fails so the caller still gets root. */
	rc = commit_common_su(to_uid, sctx);
	if (rc) {
		logkw("commit_common_su failed (%d), falling back to cred\n", rc);
		struct cred *new = kp_prepare_creds();
		if (!new)
			return -ENOMEM;
		su_cred(new, to_uid);
		kp_commit_creds(new);
		return 0;
	}
	return 0;
}

int kp_task_su(pid_t pid, uid_t to_uid, const char *sctx)
{
	struct task_struct *task;
	const struct cred *old;
	struct cred *new;

	task = kp_find_get_task_by_vpid ? kp_find_get_task_by_vpid(pid) : NULL;
	if (!task) {
		logke("task_su: no task pid %d\n", pid);
		return -ESRCH;
	}

	new = kp_prepare_creds();
	if (!new) {
		put_task_struct(task);
		return -ENOMEM;
	}
	su_cred(new, to_uid);
	(void)sctx;

	rcu_read_lock();
	old = task->cred;
	rcu_assign_pointer(task->cred, new);
	rcu_assign_pointer(task->real_cred, new);
	rcu_read_unlock();
	put_cred(old);

	put_task_struct(task);
	logki("task_su: pid %d -> uid %u\n", pid, to_uid);
	return 0;
}
