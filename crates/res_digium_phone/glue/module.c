/*
 * dpma-rs - Open source Digium Phone Module for Asterisk
 *
 * Module registration.  The real work is done in Rust.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "asterisk.h"

#include "asterisk/module.h"

extern int dpma_rust_load(void);
extern int dpma_rust_unload(void);
extern int dpma_rust_reload(void);

static int load_module(void)
{
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
