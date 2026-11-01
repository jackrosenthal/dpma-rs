/*
 * dpma-rs - Open source Digium Phone Module for Asterisk
 *
 * Stasis glue: the parking topic subscription of
 * phone_method_internal_api.c (FUN_00186920 / FUN_00186840).  A topic of
 * the module's own forwards everything published on ast_parking_topic(),
 * and a message router on it hands ast_parked_call_type() messages to a
 * callback.
 *
 * Core Asterisk headers only (compiled into every module).
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "asterisk.h"

#include "asterisk/astobj2.h"
#include "asterisk/parking.h"
#include "asterisk/stasis.h"
#include "asterisk/stasis_message_router.h"

typedef void (*dpma_parked_call_fn)(const char *parker_dial_string, int event_type, unsigned int parkingspace);

static struct stasis_topic *parking_topic;
static struct stasis_forward *parking_forward;
static struct stasis_message_router *parking_router;
static dpma_parked_call_fn parked_call_fn;

static void parked_call_message(void *data, struct stasis_subscription *sub, struct stasis_message *message)
{
	struct ast_parked_call_payload *payload = stasis_message_data(message);

	if (payload && parked_call_fn) {
		parked_call_fn(payload->parker_dial_string, payload->event_type, payload->parkingspace);
	}
}

/*! Undo dpma_glue_stasis_parking_subscribe (also after a partial one). */
void dpma_glue_stasis_parking_unsubscribe(void)
{
	parking_forward = stasis_forward_cancel(parking_forward);
	stasis_message_router_unsubscribe_and_join(parking_router);
	parking_router = NULL;
	ao2_cleanup(parking_topic);
	parking_topic = NULL;
	parked_call_fn = NULL;
}

/*!
 * Create the topic `topic_name`, forward the parking topic to it, and
 * route parked call messages to `fn`.  0 on success; on failure everything
 * is undone and -1 is returned.
 */
int dpma_glue_stasis_parking_subscribe(const char *topic_name, dpma_parked_call_fn fn)
{
	parked_call_fn = fn;
	parking_topic = stasis_topic_create(topic_name);
	if (!parking_topic) {
		goto failure;
	}
	parking_forward = stasis_forward_all(ast_parking_topic(), parking_topic);
	if (!parking_forward) {
		goto failure;
	}
	parking_router = stasis_message_router_create(parking_topic);
	if (!parking_router) {
		goto failure;
	}
	if (stasis_message_router_add(parking_router, ast_parked_call_type(), parked_call_message, NULL)) {
		goto failure;
	}
	return 0;

failure:
	dpma_glue_stasis_parking_unsubscribe();
	return -1;
}
