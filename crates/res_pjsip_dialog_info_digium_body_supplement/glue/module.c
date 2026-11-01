/*
 * dpma-rs - Open source Digium Phone Module for Asterisk
 *
 * Module registration for res_pjsip_dialog_info_digium_body_supplement.  The work is done in Rust.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "asterisk.h"

#include "asterisk/module.h"

extern int dpma_dlg_rust_load(void);
extern int dpma_dlg_rust_unload(void);

static int load_module(void)
{
	return dpma_dlg_rust_load() ? AST_MODULE_LOAD_DECLINE : AST_MODULE_LOAD_SUCCESS;
}

static int unload_module(void)
{
	return dpma_dlg_rust_unload();
}

AST_MODULE_INFO(ASTERISK_GPL_KEY, AST_MODFLAG_LOAD_ORDER, "PJSIP Dialog-Info Digium supplement",
	.support_level = AST_MODULE_SUPPORT_EXTENDED,
	.load = load_module,
	.unload = unload_module,
	.load_pri = AST_MODPRI_DEFAULT,
	/*
	 * The implementation must declare .requires = "res_pjsip,res_digium_phone"
	 * (as the original does).  The skeleton declares no dependencies: a
	 * declined module keeps references on the modules it requires, which
	 * would prevent res_digium_phone from being unloaded.
	 */
);
