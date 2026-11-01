/*
 * dpma-rs - Open source Digium Phone Module for Asterisk
 *
 * Module registration.  The real work is done in Rust.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "asterisk.h"

#include <dlfcn.h>

#include "asterisk/module.h"

extern int dpma_rust_load(void);
extern int dpma_rust_unload(void);
extern int dpma_rust_reload(void);

/*
 * Rust's standard library registers thread-local destructors
 * (__cxa_thread_atexit_impl) on the Asterisk threads that run the module's
 * code, for example on the thread that loads the module when it spawns
 * phone_main or the mDNS responder, and glibc keeps a shared object mapped
 * while any are pending.  So "module unload" usually leaves this module
 * mapped: the loader's dlclose drops the last reference, but the image
 * stays and its destructor, which would unregister the module from the
 * loader, does not run.  The next "module load" then finds the module still
 * registered and starts it again without a dlopen, and the unload after
 * that calls dlclose on a handle that is no longer open ("Failure in
 * dlclose ... shared object not open").  So when the module is started
 * again in the same image, take the reference that the loader's next
 * dlclose drops.  (A new build still needs an Asterisk restart.)
 */
static int started_before;

static void reopen_if_restarted(void)
{
	Dl_info info;

	if (started_before && dladdr((void *) reopen_if_restarted, &info) && info.dli_fname) {
		/* Released by the loader's dlclose at the next unload. */
		if (!dlopen(info.dli_fname, RTLD_LAZY | RTLD_NOLOAD)) {
			ast_log(LOG_WARNING, "Unable to reference %s: %s\n", info.dli_fname, dlerror());
		}
	}
	started_before = 1;
}

static int load_module(void)
{
	reopen_if_restarted();
	return dpma_rust_load() ? AST_MODULE_LOAD_DECLINE : AST_MODULE_LOAD_SUCCESS;
}

static int unload_module(void)
{
	return dpma_rust_unload();
}

static int reload_module(void)
{
	return dpma_rust_reload();
}

AST_MODULE_INFO(ASTERISK_GPL_KEY, AST_MODFLAG_GLOBAL_SYMBOLS | AST_MODFLAG_LOAD_ORDER,
	"Digium Phone Module for Asterisk",
	.support_level = AST_MODULE_SUPPORT_EXTENDED,
	.load = load_module,
	.unload = unload_module,
	.reload = reload_module,
	.load_pri = AST_MODPRI_DEFAULT,
	.optional_modules = "func_presencestate,app_voicemail,res_parking,app_queue",
);
