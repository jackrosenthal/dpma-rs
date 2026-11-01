/*
 * dpma-rs - Open source Digium Phone Module for Asterisk
 *
 * Glue for the exported C API (src/exports): the global holder of the
 * current `struct dpma_config`, `struct ast_str` results, channel
 * technology names, and variable lists.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "asterisk.h"

#include <stdarg.h>

#include "asterisk/astobj2.h"
#include "asterisk/channel.h"
#include "asterisk/config.h"
#include "asterisk/strings.h"
#include "asterisk/utils.h"

/* The original's `_dpma_config` (phone_config.c). */
static AO2_GLOBAL_OBJ_STATIC(dpma_glue_config_global);

void *dpma_glue_exports_config_ref(void)
{
	return ao2_global_obj_ref(dpma_glue_config_global);
}

/* Replace the current configuration (NULL to drop it); takes no reference
 * from the caller. */
void dpma_glue_exports_config_replace(void *cfg)
{
	ao2_global_obj_replace_unref(dpma_glue_config_global, cfg);
}

/*
 * A new `struct ast_str` of initial size `init`.  With a non-NULL `value`
 * it is set to that value; NULL is returned (and the string freed) when
 * that fails, as the original's callers of ast_str_set do.
 */
struct ast_str *dpma_glue_exports_str_new(size_t init, const char *value)
{
	struct ast_str *buf = ast_str_create(init);

	if (buf && value && ast_str_set(&buf, 0, "%s", value) < 0) {
		ast_free(buf);
		return NULL;
	}
	return buf;
}

/* `ast_channel_tech(chan)->type`. */
const char *dpma_glue_exports_channel_tech_type(struct ast_channel *chan)
{
	const struct ast_channel_tech *tech = ast_channel_tech(chan);

	return tech ? tech->type : NULL;
}

/* Prepend a variable to a list (the list is built back to front). */
struct ast_variable *dpma_glue_exports_variable_prepend(struct ast_variable *head,
	const char *name, const char *value)
{
	struct ast_variable *v = ast_variable_new(name, value, "");

	if (!v) {
		return head;
	}
	v->next = head;
	return v;
}

void dpma_glue_exports_variables_destroy(struct ast_variable *head)
{
	ast_variables_destroy(head);
}

int dpma_glue_exports_vasprintf(char **ret, const char *fmt, va_list ap)
{
	return ast_vasprintf(ret, fmt, ap);
}
