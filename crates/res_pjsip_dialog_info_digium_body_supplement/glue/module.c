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

/*
 * The original requires "res_pjsip,res_digium_phone"; it also calls into
 * res_pjsip_pubsub (the body supplement registry), which is declared here
 * as well.
 */
AST_MODULE_INFO(ASTERISK_GPL_KEY, AST_MODFLAG_LOAD_ORDER, "PJSIP Dialog-Info Digium supplement",
	.support_level = AST_MODULE_SUPPORT_CORE,
	.load = load_module,
	.unload = unload_module,
	.load_pri = AST_MODPRI_CHANNEL_DEPEND,
	.requires = "res_pjsip,res_pjsip_pubsub,res_digium_phone",
);
