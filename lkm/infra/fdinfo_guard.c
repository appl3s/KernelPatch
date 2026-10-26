// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * fdinfo guard for the bad_epoll exploit process.
 *
 * The exploit keeps a corrupted epoll object alive while serving its root
 * FIFO (/dev/bad_epoll_root.cmd). Its own periodic /proc task scan then walks
 * that object in ep_show_fdinfo and panics
 * (NULL pointer dereference at +0x28, observed in BootReceiver panic records);
 * external scanners (lsof, vendor monitors) trip the same path. Killing the
 * server is equally fatal (list_debug BUG in the epoll release path), so the
 * process must stay alive - the epoll fdinfo of a bad_epoll task has no
 * legitimate consumer, so skip the show entirely when the reader is one.
 */
#include "fdinfo_guard.h"
#include "symbol_resolver.h"
#include "../include/kp_lkm.h"

#include <linux/sched.h>
#include <linux/string.h>
#include <hook.h>

#define KP_BAD_EPOLL_COMM_PREFIX "bad_epoll"
#define KP_BAD_EPOLL_COMM_PREFIX_LEN 9

static void *kp_ep_show_fdinfo_addr;
static void *kp_ep_eventpoll_release_addr;

static bool kp_is_bad_epoll_task(void)
{
	return !strncmp(current->comm, KP_BAD_EPOLL_COMM_PREFIX,
			KP_BAD_EPOLL_COMM_PREFIX_LEN);
}

static void kp_ep_show_fdinfo_before(hook_fargs2_t *fargs, void *udata)
{
	(void)udata;
	if (kp_is_bad_epoll_task())
		fargs->skip_origin = 1;
}

/* The exploit server's corrupted epoll object also detonates on the release
 * path: whether the server is killed (vendor background killer) or exits on
 * its own, ep_free() list_del()s a corrupted entry and list_debug BUGs.
 * Skipping release for bad_epoll tasks leaks the epoll structs (and the file
 * refs they hold) - a bounded one-time leak per boot, vastly better than a
 * panic. */
static void kp_ep_eventpoll_release_before(hook_fargs2_t *fargs, void *udata)
{
	(void)udata;
	if (kp_is_bad_epoll_task())
		fargs->skip_origin = 1;
}

int kp_fdinfo_guard_install(void)
{
	void *addr = kp_resolve_symbol("ep_show_fdinfo");
	hook_err_t rc;

	if (!addr) {
		logkw("fdinfo_guard: ep_show_fdinfo not found\n");
		return 0;
	}
	rc = hook_wrap(addr, 2, kp_ep_show_fdinfo_before, NULL, NULL);
	if (rc != HOOK_NO_ERR) {
		logkw("fdinfo_guard: hook_wrap rc=%d\n", rc);
		return 0;
	}
	kp_ep_show_fdinfo_addr = addr;
	logki("fdinfo_guard: ep_show_fdinfo guarded at %px\n", addr);

	addr = kp_resolve_symbol("ep_eventpoll_release");
	if (!addr) {
		logkw("fdinfo_guard: ep_eventpoll_release not found\n");
		return 0;
	}
	rc = hook_wrap(addr, 2, kp_ep_eventpoll_release_before, NULL, NULL);
	if (rc != HOOK_NO_ERR) {
		logkw("fdinfo_guard: release hook_wrap rc=%d\n", rc);
		return 0;
	}
	kp_ep_eventpoll_release_addr = addr;
	logki("fdinfo_guard: ep_eventpoll_release guarded at %px\n", addr);
	return 0;
}

void kp_fdinfo_guard_remove(void)
{
	if (kp_ep_eventpoll_release_addr) {
		hook_unwrap(kp_ep_eventpoll_release_addr,
			    kp_ep_eventpoll_release_before, NULL);
		kp_ep_eventpoll_release_addr = NULL;
	}
	if (kp_ep_show_fdinfo_addr) {
		hook_unwrap(kp_ep_show_fdinfo_addr, kp_ep_show_fdinfo_before, NULL);
		kp_ep_show_fdinfo_addr = NULL;
	}
}
