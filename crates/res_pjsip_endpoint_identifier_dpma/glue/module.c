/*
 * dpma-rs - Open source Digium Phone Module for Asterisk
 *
 * Module registration for res_pjsip_endpoint_identifier_dpma.  The work is done in Rust.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "asterisk.h"

#include "asterisk/module.h"

extern int dpma_eid_rust_load(void);
extern int dpma_eid_rust_unload(void);

/* The Rust side returns the AST_MODULE_LOAD_* result itself: the original
 * fails with AST_MODULE_LOAD_FAILURE (-1). */
static int load_module(void)
{
	return dpma_eid_rust_load();
}

static int unload_module(void)
{
	return dpma_eid_rust_unload();
}

AST_MODULE_INFO(ASTERISK_GPL_KEY, AST_MODFLAG_LOAD_ORDER, "DPMA PJSIP Support",
	.support_level = AST_MODULE_SUPPORT_EXTENDED,
	.load = load_module,
	.unload = unload_module,
	.load_pri = AST_MODPRI_DEFAULT,
	.requires = "res_pjsip,res_digium_phone",
);
