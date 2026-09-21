// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 *
 * Runtime symbol resolver. This kernel does NOT export kallsyms_lookup_name to
 * modules, so we must never link it: the load script reads its address from
 * /proc/kallsyms and passes it as the module_param `kln`. Every other symbol
 * is then recovered through kp_resolve_symbol(). kallsyms_on_each_symbol is
 * resolved by name for CFI/llvm-mangled variant matching.
 */
#include "symbol_resolver.h"

#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/string.h>
#include <linux/version.h>

#include "../include/kp_lkm.h"

/* kallsyms_on_each_symbol() dropped the struct module * param from its
 * callback in 6.4; the callback and this fn-pointer type must match the
 * running kernel (kCFI type-hash at the indirect call). */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
typedef int (*kp_kallsyms_on_each_symbol_t)(int (*fn)(void *, const char *, unsigned long),
					    void *data);
#else
typedef int (*kp_kallsyms_on_each_symbol_t)(int (*fn)(void *, const char *, struct module *, unsigned long),
					    void *data);
#endif

/* Bootstrap kallsyms_lookup_name address, passed by the load script as
 * `insmod kernelpatch.ko kln=0x<addr>` (from /proc/kallsyms). This is what
 * makes the .ko stable across boots: no ELF UND, no abs-patch. */
static unsigned long kln_addr;
module_param_named(kln, kln_addr, ulong, 0);

/* Typed pointer for the indirect lookup call. */
static unsigned long (*kp_kln)(const char *name);

/* Recovered by name at init; NULL if the kernel hides it. */
static kp_kallsyms_on_each_symbol_t kp_on_each_symbol;

/* kCFI: kp_symres_init() runs before the secpass CFI shield is up, and the
 * pointer was fabricated from a module_param so the type-hash is not visible
 * to the compiler — keep the indirect call unsanitized. */
__attribute__((no_sanitize("cfi")))
unsigned long kp_resolve_symbol(const char *name)
{
	if (!kp_kln)
		return 0;
	return kp_kln(name);
}

struct kp_variant_ctx {
	const char *name;
	size_t name_len;
	unsigned long exact;
	unsigned long variant;
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
static int kp_variant_cb(void *data, const char *name, unsigned long addr)
#else
static int kp_variant_cb(void *data, const char *name, struct module *m, unsigned long addr)
#endif
{
	struct kp_variant_ctx *ctx = data;
	size_t nlen;
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
	(void)m;
#endif

	if (!name || !addr)
		return 0;
	nlen = strlen(name);

	if (!strcmp(name, ctx->name)) {
		ctx->exact = addr;
		return 1; /* exact match is always best; stop */
	}
	if (nlen > ctx->name_len && !strncmp(name, ctx->name, ctx->name_len) &&
	    (name[ctx->name_len] == '.' || name[ctx->name_len] == '$')) {
		if (!ctx->variant)
			ctx->variant = addr;
	}
	return 0;
}

void *kp_resolve_symbol_variant(const char *name)
{
	/* Traditional CFI (< 6.1) requires calling functions through their .cfi_jt
	 * canonical-jump-table entry, not the function body — a direct indirect
	 * call to the body trips __cfi_check (panic). Prefer the .cfi_jt variant,
	 * then the exact symbol, then any .llvm.<hash> mangled name. */
	char cfi_name[KSYM_NAME_LEN];
	int n = snprintf(cfi_name, sizeof(cfi_name), "%s.cfi_jt", name);
	if (n > 0 && n < (int)sizeof(cfi_name)) {
		unsigned long jt = kp_resolve_symbol(cfi_name);
		if (jt)
			return (void *)jt;
	}

	struct kp_variant_ctx ctx = { .name = name, .name_len = strlen(name) };

	ctx.exact = kp_resolve_symbol(name);
	if (ctx.exact)
		return (void *)ctx.exact;
	if (kp_on_each_symbol) {
		kp_on_each_symbol(kp_variant_cb, &ctx);
		return (void *)ctx.variant;
	}
	return NULL;
}

int kp_symres_init(void)
{
	if (!kln_addr) {
		logke("kln= module_param missing; pass kallsyms_lookup_name address "
		      "from /proc/kallsyms (insmod kernelpatch.ko kln=0x<addr>)\n");
		return -EINVAL;
	}
	kp_kln = (unsigned long (*)(const char *))kln_addr;
	kp_on_each_symbol = (kp_kallsyms_on_each_symbol_t)kp_resolve_symbol("kallsyms_on_each_symbol");
	logki("symbol resolver ready (kln=%px on_each_symbol=%px)\n",
	      (void *)kln_addr, (void *)kp_on_each_symbol);
	return 0;
}
