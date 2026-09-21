#include "kfuncs.h"
#include "symbol_resolver.h"

#include <linux/err.h>
#include <linux/errno.h>
#include <linux/uaccess.h>

#include "../include/kp_lkm.h"

typedef struct file *(*fn_filp_open_t)(const char *, int, umode_t);
typedef ssize_t (*fn_kernel_read_t)(struct file *, void *, size_t, loff_t *);
typedef void (*fn_abort_creds_t)(struct cred *);
typedef int (*fn_commit_creds_t)(struct cred *);
typedef struct cred *(*fn_prepare_creds_t)(void);
typedef int (*fn_secctx_to_secid_t)(const char *, u32, u32 *);

static fn_filp_open_t fn_filp_open;
static fn_kernel_read_t fn_kernel_read;
static fn_abort_creds_t fn_abort_creds;
static fn_commit_creds_t fn_commit_creds;
static fn_prepare_creds_t fn_prepare_creds;
static fn_secctx_to_secid_t fn_secctx_to_secid;

static int resolve_one(const char *name, unsigned long *slot)
{
	unsigned long addr = kp_resolve_symbol(name);

	if (!addr) {
		logke("kfuncs: failed to resolve %s\n", name);
		return -ENOENT;
	}
	*slot = addr;
	return 0;
}

int kp_kfuncs_init(void)
{
	int rc;

	rc = resolve_one("filp_open", (unsigned long *)&fn_filp_open);
	if (rc)
		return rc;
	rc = resolve_one("kernel_read", (unsigned long *)&fn_kernel_read);
	if (rc)
		return rc;
	rc = resolve_one("abort_creds", (unsigned long *)&fn_abort_creds);
	if (rc)
		return rc;
	rc = resolve_one("commit_creds", (unsigned long *)&fn_commit_creds);
	if (rc)
		return rc;
	rc = resolve_one("prepare_creds", (unsigned long *)&fn_prepare_creds);
	if (rc)
		return rc;
	rc = resolve_one("security_secctx_to_secid", (unsigned long *)&fn_secctx_to_secid);
	if (rc)
		return rc;
	logki("kfuncs resolved (filp_open/kernel_read/creds/secctx)\n");
	return 0;
}

__attribute__((no_sanitize("cfi")))
struct file *kp_filp_open(const char *filename, int flags, umode_t mode)
{
	if (!fn_filp_open)
		return ERR_PTR(-ENOENT);
	return fn_filp_open(filename, flags, mode);
}

__attribute__((no_sanitize("cfi")))
ssize_t kp_kernel_read(struct file *file, void *buf, size_t count, loff_t *pos)
{
	if (!fn_kernel_read)
		return -ENOENT;
	return fn_kernel_read(file, buf, count, pos);
}

__attribute__((no_sanitize("cfi")))
void kp_abort_creds(struct cred *cred)
{
	if (fn_abort_creds)
		fn_abort_creds(cred);
}

__attribute__((no_sanitize("cfi")))
int kp_commit_creds(struct cred *new)
{
	if (!fn_commit_creds)
		return -ENOENT;
	return fn_commit_creds(new);
}

__attribute__((no_sanitize("cfi")))
struct cred *kp_prepare_creds(void)
{
	if (!fn_prepare_creds)
		return NULL;
	return fn_prepare_creds();
}

__attribute__((no_sanitize("cfi")))
int kp_security_secctx_to_secid(const char *secdata, u32 seclen, u32 *secid)
{
	if (!fn_secctx_to_secid)
		return -ENOENT;
	return fn_secctx_to_secid(secdata, seclen, secid);
}
