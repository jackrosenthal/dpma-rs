/*
 * dpma-rs - Open source Digium Phone Module for Asterisk
 *
 * Channel glue: lookups by name prefix and technology call id, the
 * channel's name and unique id under its lock, and the scan for a queue
 * member's current call (phone_method_internal_api.c).
 *
 * Core Asterisk headers only (compiled into every module).
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "asterisk.h"

#include <string.h>
#include <strings.h>
#include <sys/time.h>

#include "asterisk/channel.h"
#include "asterisk/pbx.h"
#include "asterisk/strings.h"
#include "asterisk/utils.h"

/*!
 * `find_channel_by_callid_tech` (FUN_0017afa0): the first channel whose
 * name starts with `prefix` (the original passes "<tech>/<account>") and
 * whose technology reports `callid` as its private unique id (for PJSIP,
 * the SIP Call-ID).  Returns a new reference, or NULL.
 */
struct ast_channel *dpma_glue_channel_find_by_callid(const char *prefix, const char *callid)
{
	struct ast_channel_iterator *iter;
	struct ast_channel *chan;

	iter = ast_channel_iterator_by_name_new(prefix, strlen(prefix));
	if (!iter) {
		return NULL;
	}
	while ((chan = ast_channel_iterator_next(iter))) {
		ast_channel_lock(chan);
		if (ast_channel_tech(chan)->get_pvt_uniqueid
			&& !strcmp(callid, ast_channel_tech(chan)->get_pvt_uniqueid(chan))) {
			ast_channel_unlock(chan);
			break;
		}
		ast_channel_unlock(chan);
		ast_channel_unref(chan);
	}
	ast_channel_iterator_destroy(iter);
	return chan;
}

/*! Drop a channel reference. */
void dpma_glue_channel_unref(struct ast_channel *chan)
{
	ast_channel_unref(chan);
}

/*!
 * The channel's name and unique id, read under the channel lock, as
 * ast_malloc'ed strings (the caller frees them with dpma_glue_free).
 */
void dpma_glue_channel_name_uniqueid(struct ast_channel *chan, char **name, char **uniqueid)
{
	ast_channel_lock(chan);
	*name = ast_strdup(ast_channel_name(chan));
	*uniqueid = ast_strdup(ast_channel_uniqueid(chan));
	ast_channel_unlock(chan);
}

/*!
 * The scan in `handle_request_json_queue_gettodaysstatus`: the first
 * channel whose MEMBERINTERFACE variable equals `interface` (case
 * insensitive; an unset variable counts as "") and whose QUEUEPOSITION is
 * unset or empty, i.e., a queue member's leg of a queue call.  Returns 1
 * and its creation time (seconds) in `*created`, or 0 when there is none.
 */
int dpma_glue_channel_queue_member_call(const char *interface, long *created)
{
	struct ast_channel_iterator *iter;
	struct ast_channel *chan;

	iter = ast_channel_iterator_all_new();
	if (!iter) {
		return 0;
	}
	while ((chan = ast_channel_iterator_next(iter))) {
		const char *member;
		const char *position;

		ast_channel_lock(chan);
		member = pbx_builtin_getvar_helper(chan, "MEMBERINTERFACE");
		if (!strcasecmp(S_OR(member, ""), interface)) {
			position = pbx_builtin_getvar_helper(chan, "QUEUEPOSITION");
			if (ast_strlen_zero(position)) {
				*created = (long) ast_channel_creationtime(chan).tv_sec;
				ast_channel_unlock(chan);
				ast_channel_unref(chan);
				ast_channel_iterator_destroy(iter);
				return 1;
			}
		}
		ast_channel_unlock(chan);
		ast_channel_unref(chan);
	}
	ast_channel_iterator_destroy(iter);
	return 0;
}
