/*
 * dpma-rs - Open source Digium Phone Module for Asterisk
 *
 * PJSIP glue for res_pjsip_dialog_info_digium_body_supplement: the body
 * supplement registration, the ringing channel lookup, and accessors for
 * the extension state data, channel party information, and pjlib XML
 * nodes.  The supplement itself is in Rust (src/lib.rs).
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "asterisk.h"

#include <pjsip.h>
#include <pjlib.h>

#include "asterisk/astobj2.h"
#include "asterisk/callerid.h"
#include "asterisk/channel.h"
#include "asterisk/pbx.h"
#include "asterisk/res_pjsip.h"
#include "asterisk/res_pjsip_pubsub.h"
#include "asterisk/res_pjsip_body_generator_types.h"

/* ------------------------------------------------------------------ */
/* Registration                                                        */
/* ------------------------------------------------------------------ */

extern int dpma_dlg_rust_supplement_body(void *body, void *data);

static struct ast_sip_pubsub_body_supplement dialog_info_supplement = {
	.type = "application",
	.subtype = "dialog-info+xml",
	.supplement_body = dpma_dlg_rust_supplement_body,
};

int dpma_dlg_glue_register(void)
{
	return ast_sip_pubsub_register_body_supplement(&dialog_info_supplement);
}

void dpma_dlg_glue_unregister(void)
{
	ast_sip_pubsub_unregister_body_supplement(&dialog_info_supplement);
}

/* ------------------------------------------------------------------ */
/* Extension state data                                                */
/* ------------------------------------------------------------------ */

/* The fields of struct ast_sip_exten_state_data the supplement uses. */
struct dpma_dlg_state {
	const char *exten;
	int exten_state;
	const char *user_agent;
	struct ao2_container *device_state_info;
	const char *local;
	const char *remote;
	pj_pool_t *pool;
};

void dpma_dlg_glue_state(const struct ast_sip_exten_state_data *data, struct dpma_dlg_state *out)
{
	out->exten = data->exten;
	out->exten_state = data->exten_state;
	out->user_agent = data->user_agent;
	out->device_state_info = data->device_state_info;
	out->local = data->local;
	out->remote = data->remote;
	out->pool = data->pool;
}

/*
 * find_ringing_channel: of the channels causing a ringing device state
 * (RINGING or RINGINUSE), the oldest one, with a reference; NULL if none.
 */
struct ast_channel *dpma_dlg_glue_find_ringing_channel(struct ao2_container *device_state_info)
{
	struct ao2_iterator citer;
	struct ast_device_state_info *device_state;
	struct ast_channel *c = NULL;
	struct timeval tv = { 0, };

	citer = ao2_iterator_init(device_state_info, 0);
	for (; (device_state = ao2_iterator_next(&citer)); ao2_ref(device_state, -1)) {
		if (!device_state->causing_channel || (device_state->device_state != AST_DEVICE_RINGING
				&& device_state->device_state != AST_DEVICE_RINGINUSE)) {
			continue;
		}
		ast_channel_lock(device_state->causing_channel);
		if (ast_tvzero(tv) || ast_tvcmp(ast_channel_creationtime(device_state->causing_channel), tv) < 0) {
			if (c) {
				ao2_ref(c, -1);
			}
			c = device_state->causing_channel;
			tv = ast_channel_creationtime(c);
			ao2_ref(c, +1);
		}
		ast_channel_unlock(device_state->causing_channel);
	}
	ao2_iterator_destroy(&citer);
	return c;
}

/* ------------------------------------------------------------------ */
/* Channel party information                                           */
/* ------------------------------------------------------------------ */

/* An ast_party_id: whether name and number are restricted
 * ((presentation & AST_PRES_RESTRICTION) == AST_PRES_RESTRICTED) and
 * valid, and their strings. */
struct dpma_dlg_party {
	int number_restricted;
	int number_valid;
	const char *number;
	int name_restricted;
	int name_valid;
	const char *name;
};

static void party(const struct ast_party_id *id, struct dpma_dlg_party *out)
{
	out->number_restricted = (id->number.presentation & AST_PRES_RESTRICTION) == AST_PRES_RESTRICTED;
	out->number_valid = id->number.valid;
	out->number = id->number.str;
	out->name_restricted = (id->name.presentation & AST_PRES_RESTRICTION) == AST_PRES_RESTRICTED;
	out->name_valid = id->name.valid;
	out->name = id->name.str;
}

/* The caller (connected == 0) or connected line (connected != 0) party of
 * a locked channel.  The strings stay valid while the channel is locked. */
void dpma_dlg_glue_party(struct ast_channel *chan, int connected, struct dpma_dlg_party *out)
{
	if (connected) {
		party(&ast_channel_connected(chan)->id, out);
	} else {
		party(&ast_channel_caller(chan)->id, out);
	}
}

/* ------------------------------------------------------------------ */
/* XML nodes                                                           */
/* ------------------------------------------------------------------ */

/* The first child of `parent` called `name`, or NULL. */
pj_xml_node *dpma_dlg_glue_find_node(const pj_xml_node *parent, const char *name)
{
	pj_str_t s = { (char *) name, strlen(name) };

	return pj_xml_find_node(parent, &s);
}

/* Set the text content of `node` (allocated from `pool`). */
void dpma_dlg_glue_set_content(pj_pool_t *pool, pj_xml_node *node, const char *text)
{
	pj_strdup2(pool, &node->content, text);
}
