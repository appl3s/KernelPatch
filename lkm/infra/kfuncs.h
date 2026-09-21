#ifndef _KP_LKM_KFUNCS_H_
#define _KP_LKM_KFUNCS_H_

#include <linux/fs.h>
#include <linux/cred.h>
#include <linux/types.h>

int kp_kfuncs_init(void);

struct file *kp_filp_open(const char *filename, int flags, umode_t mode);
ssize_t kp_kernel_read(struct file *file, void *buf, size_t count, loff_t *pos);
void kp_abort_creds(struct cred *cred);
int kp_commit_creds(struct cred *new);
struct cred *kp_prepare_creds(void);
int kp_security_secctx_to_secid(const char *secdata, u32 seclen, u32 *secid);

#endif
