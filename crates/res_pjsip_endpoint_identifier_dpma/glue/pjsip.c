/*
 * dpma-rs - Open source Digium Phone Module for Asterisk
 *
 * PJSIP glue for res_pjsip_endpoint_identifier_dpma: the endpoint that
 * incoming DPMA requests are matched to (`g_endpoint`), the endpoint
 * identifier, the SIP INFO sender behind the "PJSIP" info handler, and
 * accessors for PJSIP structures.  The rest of the module is in Rust
 * (src/lib.rs).
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "asterisk.h"

#include <dlfcn.h>

#include <pjsip.h>
#include <pjsip_ua.h>
#include <pjlib.h>

#include "asterisk/astobj2.h"
#include "asterisk/channel.h"
#include "asterisk/config.h"
#include "asterisk/res_pjsip.h"
#include "asterisk/res_pjsip_session.h"
#include "asterisk/strings.h"

/* ------------------------------------------------------------------ */
/* The endpoint for DPMA requests                                      */
/* ------------------------------------------------------------------ */

static AO2_GLOBAL_OBJ_STATIC(g_endpoint);

/* The endpoint with a reference, or NULL. */
struct ast_sip_endpoint *dpma_eid_glue_endpoint_ref(void)
{
	return ao2_global_obj_ref(g_endpoint);
}

/* Replace the endpoint (NULL to drop it); takes no reference. */
void dpma_eid_glue_endpoint_replace(struct ast_sip_endpoint *endpoint)
{
	ao2_global_obj_replace_unref(g_endpoint, endpoint);
}

/* ------------------------------------------------------------------ */
/* Endpoint identifier (identify_endpoint)                             */
/* ------------------------------------------------------------------ */

static const pj_str_t x_digium_user_agent = { "X-Digium-User-Agent", 19 };

/*
 * A request carrying an X-Digium-User-Agent header comes from a phone
 * talking to the module: it gets the DPMA endpoint.  (The original finds
 * rdata->msg_info.msg by scanning rdata for msg_info.info, the word after
 * it, so that it works with any layout of pjsip_rx_data; this glue is
 * compiled against the headers instead.)
 */
static struct ast_sip_endpoint *identify_endpoint(pjsip_rx_data *rdata)
{
	if (!pjsip_msg_find_hdr_by_name(rdata->msg_info.msg, &x_digium_user_agent, NULL)) {
		return NULL;
	}
	return ao2_global_obj_ref(g_endpoint);
}

static struct ast_sip_endpoint_identifier dpma_identifier = {
	.identify_endpoint = identify_endpoint,
};

int dpma_eid_glue_register_identifier(void)
{
	return ast_sip_register_endpoint_identifier(&dpma_identifier);
}

void dpma_eid_glue_unregister_identifier(void)
{
	ast_sip_unregister_endpoint_identifier(&dpma_identifier);
}

/* ------------------------------------------------------------------ */
/* Accessors                                                           */
/* ------------------------------------------------------------------ */

/* `endpoint->aors`. */
const char *dpma_eid_glue_endpoint_aors(const struct ast_sip_endpoint *endpoint)
{
	return endpoint->aors;
}

/* The contact of the wrapper ast_sip_for_each_contact hands its callback. */
struct ast_sip_contact *dpma_eid_glue_wrapper_contact(const struct ast_sip_contact_wrapper *wrapper)
{
	return wrapper ? wrapper->contact : NULL;
}

/* `ast_variable_new(name, value, filename)`. */
struct ast_variable *dpma_eid_glue_variable_new(const char *name, const char *value, const char *filename)
{
	return ast_variable_new(name, value, filename);
}

/* ao2_callback(lines, OBJ_NODATA | OBJ_MULTIPLE, cb, NULL): calls `cb` for
 * every object with the container locked. */
void dpma_eid_glue_callback_all(struct ao2_container *c, ao2_callback_fn *cb)
{
	ao2_callback(c, OBJ_NODATA | OBJ_MULTIPLE, cb, NULL);
}

/* ------------------------------------------------------------------ */
/* SIP INFO (pjsip_send_info)                                          */
/* ------------------------------------------------------------------ */

typedef pjsip_dialog *(*session_get_dialog_fn)(const struct ast_sip_session *session);

/* For an Asterisk without ast_sip_session_get_dialog(). */
static pjsip_dialog *internal_session_get_dialog(const struct ast_sip_session *session)
{
	if (!session || !session->inv_session) {
		return NULL;
	}
	return session->inv_session->dlg;
}

static session_get_dialog_fn session_get_dialog = internal_session_get_dialog;

/*
 * Use Asterisk's ast_sip_session_get_dialog() when it has one (looked up
 * at run time, as the original does).  Returns 1 when found, 0 when the
 * internal accessor is used.
 */
int dpma_eid_glue_init_get_dialog(void)
{
	session_get_dialog_fn fn = (session_get_dialog_fn) dlsym(RTLD_DEFAULT, "ast_sip_session_get_dialog");

	session_get_dialog = fn ? fn : internal_session_get_dialog;
	return fn ? 1 : 0;
}

struct info_data {
	struct ast_sip_session *session;
	struct ast_variable *headers;
	const char *content_type;
	const char *body;
};

/* Runs on the session's serializer. */
static int send_info_task(void *obj)
{
	struct info_data *data = obj;
	char *content_type = ast_strdupa(S_OR(data->content_type, ""));
	struct ast_sip_body body = { .body_text = data->body, };
	struct ast_variable *var;
	pjsip_dialog *dlg;
	pjsip_tx_data *tdata;

	if (!ast_strlen_zero(data->body)) {
		body.type = strsep(&content_type, "/");
		body.subtype = content_type;
		if (ast_strlen_zero(body.type) || ast_strlen_zero(body.subtype)) {
			return -1;
		}
	}

	dlg = session_get_dialog(data->session);
	if (!dlg || ast_sip_create_request("INFO", dlg, data->session->endpoint, NULL, NULL, &tdata)) {
		return -1;
	}

	for (var = data->headers; var; var = var->next) {
		if (ast_sip_add_header(tdata, var->name, var->value)) {
			pjsip_tx_data_dec_ref(tdata);
			return -1;
		}
	}

	if (!ast_strlen_zero(data->body) && ast_sip_add_body(tdata, &body)) {
		pjsip_tx_data_dec_ref(tdata);
		return -1;
	}

	ast_sip_session_send_request(data->session, tdata);
	return 0;
}

/*
 * The `send` callback of the "PJSIP" info handler: an INFO request on the
 * channel's dialog with `headers` and, when `body` is not empty, the body
 * with `content_type` ("type/subtype").  0 when sent, else -1.  The last
 * argument (`useragent_filter`) is ignored, as in the original.
 *
 * Deviation: the original dereferences the channel's PJSIP private data
 * unchecked and would crash on a channel that is already hung up (NULL
 * tech_pvt); this returns -1 instead.
 */
int dpma_eid_glue_send_info(struct ast_channel *chan, struct ast_variable *headers,
	const char *content_type, const char *body, const char *useragent_filter)
{
	struct ast_sip_channel_pvt *channel = ast_channel_tech_pvt(chan);
	struct info_data data;

	if (!channel || !channel->session) {
		return -1;
	}
	data.session = channel->session;
	data.headers = headers;
	data.content_type = content_type;
	data.body = body;

	if (!ast_strlen_zero(body) && ast_strlen_zero(content_type)) {
		return -1;
	}

	return ast_sip_push_task_wait_servant(data.session->serializer, send_info_task, &data);
}
