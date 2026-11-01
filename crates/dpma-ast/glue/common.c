/*
 * dpma-rs - Open source Digium Phone Module for Asterisk
 *
 * Common C glue shared by all modules of this project.  Everything that
 * depends on Asterisk macros, inline functions, or struct layouts lives here
 * so that the Rust side only sees plain C functions.
 *
 * This file is compiled separately into every module with that module's
 * AST_MODULE and AST_MODULE_SELF_SYM definitions.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "asterisk.h"

#include <stdlib.h>
#include <string.h>

#include "asterisk/astdb.h"
#include "asterisk/cli.h"
#include "asterisk/config.h"
#include "asterisk/logger.h"
#include "asterisk/manager.h"
#include "asterisk/message.h"
#include "asterisk/module.h"
#include "asterisk/options.h"
#include "asterisk/paths.h"
#include "asterisk/pbx.h"
#include "asterisk/strings.h"
#include "asterisk/utils.h"

/* ------------------------------------------------------------------ */
/* Logging                                                            */
/* ------------------------------------------------------------------ */

void dpma_glue_log(int level, const char *file, int line, const char *func, const char *msg)
{
	ast_log(level, file, line, func, "%s", msg);
}

int dpma_glue_debug_atleast(int level)
{
	return DEBUG_ATLEAST(level);
}

int dpma_glue_verbose_atleast(int level)
{
	return option_verbose >= level && ast_verb_sys_level >= level;
}

int dpma_glue_fully_booted(void)
{
	return ast_test_flag(&ast_options, AST_OPT_FLAG_FULLY_BOOTED) ? 1 : 0;
}

const char *dpma_glue_var_dir(void)
{
	return ast_config_AST_VAR_DIR;
}

const char *dpma_glue_config_dir(void)
{
	return ast_config_AST_CONFIG_DIR;
}

void dpma_glue_free(void *ptr)
{
	ast_free(ptr);
}

char *dpma_glue_strdup(const char *s)
{
	return ast_strdup(s);
}

/*
 * Some Asterisk APIs keep the string pointers they are given instead of
 * copying them.  Strings passed to those come through here: each distinct
 * string is copied once and lives as long as the module, so registering the
 * same name again (e.g. after a reload) reuses the copy.
 */
#define DPMA_MAX_INTERNED 64
static char *interned[DPMA_MAX_INTERNED];
AST_MUTEX_DEFINE_STATIC(interned_lock);

const char *dpma_glue_intern(const char *str)
{
	const char *res = NULL;
	int i;

	ast_mutex_lock(&interned_lock);
	for (i = 0; i < DPMA_MAX_INTERNED && interned[i]; i++) {
		if (!strcmp(interned[i], str)) {
			res = interned[i];
			break;
		}
	}
	if (!res && i < DPMA_MAX_INTERNED) {
		interned[i] = ast_strdup(str);
		res = interned[i];
	}
	ast_mutex_unlock(&interned_lock);
	if (!res) {
		ast_log(LOG_ERROR, "Unable to keep a copy of '%s'\n", str);
	}
	return res;
}

/* ------------------------------------------------------------------ */
/* Configuration                                                      */
/* ------------------------------------------------------------------ */

struct ast_config *dpma_glue_config_load(const char *filename, const char *who, unsigned int flags)
{
	struct ast_flags f = { flags };

	return ast_config_load2(filename, who, f);
}

int dpma_glue_config_status(const struct ast_config *cfg)
{
	if (!cfg) {
		return 0; /* missing */
	}
	if (cfg == CONFIG_STATUS_FILEUNCHANGED) {
		return 1;
	}
	if (cfg == CONFIG_STATUS_FILEINVALID) {
		return 2;
	}
	return 3; /* ok */
}

const char *dpma_glue_variable_name(const struct ast_variable *v)
{
	return v->name;
}

const char *dpma_glue_variable_value(const struct ast_variable *v)
{
	return v->value;
}

int dpma_glue_variable_lineno(const struct ast_variable *v)
{
	return v->lineno;
}

const struct ast_variable *dpma_glue_variable_next(const struct ast_variable *v)
{
	return v->next;
}

/* ------------------------------------------------------------------ */
/* CLI                                                                */
/* ------------------------------------------------------------------ */

/* Implemented in Rust. */
extern int dpma_rust_cli_exec(int id, int fd, int argc, const char * const *argv);
extern char *dpma_rust_cli_complete(int id, const char *line, const char *word, int pos, int n);

struct cli_set {
	struct ast_cli_entry *entries;
	int *ids;
	int count;
	struct cli_set *next;
};

static AST_RWLIST_HEAD_STATIC(cli_sets, cli_set);

static int cli_entry_id(struct ast_cli_entry *e)
{
	struct cli_set *set;
	int id = -1;

	AST_RWLIST_RDLOCK(&cli_sets);
	for (set = AST_RWLIST_FIRST(&cli_sets); set; set = set->next) {
		if (e >= set->entries && e < set->entries + set->count) {
			id = set->ids[e - set->entries];
			break;
		}
	}
	AST_RWLIST_UNLOCK(&cli_sets);
	return id;
}

static char *cli_trampoline(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	int id;
	int res;

	if (cmd == CLI_INIT) {
		/* command and usage were filled in at registration time */
		return NULL;
	}

	id = cli_entry_id(e);
	if (id < 0) {
		return CLI_FAILURE;
	}

	if (cmd == CLI_GENERATE) {
		return dpma_rust_cli_complete(id, a->line, a->word, a->pos, a->n);
	}

	res = dpma_rust_cli_exec(id, a->fd, a->argc, a->argv);
	switch (res) {
	case 0:
		return CLI_SUCCESS;
	case 1:
		return CLI_SHOWUSAGE;
	default:
		return CLI_FAILURE;
	}
}

/*!
 * Register a set of CLI commands.  Returns an opaque handle used for
 * unregistering, or NULL on failure.
 */
void *dpma_glue_cli_register(const char * const *commands, const char * const *summaries,
	const char * const *usages, const int *ids, int count)
{
	struct cli_set *set;
	int i;

	set = ast_calloc(1, sizeof(*set));
	if (!set) {
		return NULL;
	}
	set->entries = ast_calloc(count, sizeof(*set->entries));
	set->ids = ast_calloc(count, sizeof(*set->ids));
	if (!set->entries || !set->ids) {
		ast_free(set->entries);
		ast_free(set->ids);
		ast_free(set);
		return NULL;
	}
	set->count = count;

	for (i = 0; i < count; i++) {
		struct ast_cli_entry tmp = {
			.handler = cli_trampoline,
			.summary = ast_strdup(summaries[i]),
		};

		memcpy(&set->entries[i], &tmp, sizeof(tmp));
		set->entries[i].command = ast_strdup(commands[i]);
		set->entries[i].usage = ast_strdup(usages[i]);
		set->ids[i] = ids[i];
	}

	AST_RWLIST_WRLOCK(&cli_sets);
	set->next = AST_RWLIST_FIRST(&cli_sets);
	AST_RWLIST_FIRST(&cli_sets) = set;
	AST_RWLIST_UNLOCK(&cli_sets);

	if (ast_cli_register_multiple(set->entries, count)) {
		ast_log(LOG_ERROR, "Unable to register CLI commands\n");
	}

	return set;
}

void dpma_glue_cli_unregister(void *handle)
{
	struct cli_set *set = handle;
	struct cli_set *cur, *prev = NULL;
	int i;

	if (!set) {
		return;
	}

	ast_cli_unregister_multiple(set->entries, set->count);

	AST_RWLIST_WRLOCK(&cli_sets);
	for (cur = AST_RWLIST_FIRST(&cli_sets); cur; prev = cur, cur = cur->next) {
		if (cur == set) {
			if (prev) {
				prev->next = cur->next;
			} else {
				AST_RWLIST_FIRST(&cli_sets) = cur->next;
			}
			break;
		}
	}
	AST_RWLIST_UNLOCK(&cli_sets);

	for (i = 0; i < set->count; i++) {
		ast_free((char *) set->entries[i].summary);
		ast_free(set->entries[i].command);
		ast_free((char *) set->entries[i].usage);
	}
	ast_free(set->entries);
	ast_free(set->ids);
	ast_free(set);
}

void dpma_glue_cli_out(int fd, const char *text)
{
	ast_cli(fd, "%s", text);
}

/* ------------------------------------------------------------------ */
/* Manager                                                            */
/* ------------------------------------------------------------------ */

extern int dpma_rust_manager_action(struct mansession *s, const struct message *m);

static int manager_trampoline(struct mansession *s, const struct message *m)
{
	return dpma_rust_manager_action(s, m);
}

int dpma_glue_manager_register(const char *action, int authority, const char *synopsis,
	const char *description)
{
	/* ast_manager_register2() keeps the action name pointer. */
	const char *name = dpma_glue_intern(action);

	if (!name) {
		return -1;
	}
	return ast_manager_register2(name, authority, manager_trampoline, AST_MODULE_SELF,
		synopsis, description);
}

void dpma_glue_manager_unregister(const char *action)
{
	ast_manager_unregister(action);
}

void dpma_glue_astman_append(struct mansession *s, const char *text)
{
	astman_append(s, "%s", text);
}

void dpma_glue_manager_event(int category, const char *event, const char *body)
{
	manager_event(category, event, "%s", body);
}

/*
 * manager_event() with an explicit origin: the File, Line, and Func headers
 * the event carries when manager debug is on.
 */
void dpma_glue_manager_event_at(int category, const char *event, const char *file, int line,
	const char *func, const char *body)
{
	__ast_manager_event_multichan(category, event, 0, NULL, file, line, func, "%s", body);
}

int dpma_glue_eventflag_system(void)
{
	return EVENT_FLAG_SYSTEM;
}

int dpma_glue_eventflag_config(void)
{
	return EVENT_FLAG_CONFIG;
}

int dpma_glue_eventflag_reporting(void)
{
	return EVENT_FLAG_REPORTING;
}

/*!
 * Send an action through the in-process manager hook.  The response text is
 * collected and returned as an ast_malloc'ed string (caller frees with
 * dpma_glue_free).
 */
struct hook_buf {
	struct ast_str *str;
};

AST_THREADSTORAGE(hook_buf_ts);

static int hook_collect(int category, const char *event, char *content)
{
	struct ast_str **buf = ast_threadstorage_get(&hook_buf_ts, sizeof(struct ast_str *));

	if (buf && *buf) {
		ast_str_append(buf, 0, "%s", content);
	}
	return 0;
}

char *dpma_glue_manager_hook_action(const char *action_text)
{
	struct manager_custom_hook hook = {
		.file = (char *) "dpma",
		.helper = hook_collect,
	};
	struct ast_str **buf = ast_threadstorage_get(&hook_buf_ts, sizeof(struct ast_str *));
	char *result;

	if (!buf) {
		return NULL;
	}
	*buf = ast_str_create(1024);
	if (!*buf) {
		return NULL;
	}
	ast_hook_send_action(&hook, action_text);
	result = ast_strdup(ast_str_buffer(*buf));
	ast_free(*buf);
	*buf = NULL;
	return result;
}

/* ------------------------------------------------------------------ */
/* Out of call messaging                                              */
/* ------------------------------------------------------------------ */

extern int dpma_rust_msg_received(const struct ast_msg *msg, const char *to, const char *from);

static int msg_send_trampoline(const struct ast_msg *msg, const char *to, const char *from)
{
	return dpma_rust_msg_received(msg, to, from);
}

static const struct ast_msg_tech dpma_msg_tech = {
	.name = "digium_phone",
	.msg_send = msg_send_trampoline,
};

int dpma_glue_msg_tech_register(void)
{
	return ast_msg_tech_register(&dpma_msg_tech);
}

int dpma_glue_msg_tech_unregister(void)
{
	return ast_msg_tech_unregister(&dpma_msg_tech);
}

int dpma_glue_msg_set_context(struct ast_msg *msg, const char *value)
{
	return ast_msg_set_context(msg, "%s", value);
}

int dpma_glue_msg_set_exten(struct ast_msg *msg, const char *value)
{
	return ast_msg_set_exten(msg, "%s", value);
}

int dpma_glue_msg_set_body(struct ast_msg *msg, const char *value)
{
	return ast_msg_set_body(msg, "%s", value);
}

int dpma_glue_msg_set_from(struct ast_msg *msg, const char *value)
{
	return ast_msg_set_from(msg, "%s", value);
}

int dpma_glue_msg_set_to(struct ast_msg *msg, const char *value)
{
	return ast_msg_set_to(msg, "%s", value);
}

struct ast_msg *dpma_glue_msg_ref(const struct ast_msg *msg)
{
	return ast_msg_ref((struct ast_msg *) msg);
}

/* ------------------------------------------------------------------ */
/* AstDB                                                              */
/* ------------------------------------------------------------------ */

const struct ast_db_entry *dpma_glue_db_entry_next(const struct ast_db_entry *e)
{
	return e->next;
}

const char *dpma_glue_db_entry_key(const struct ast_db_entry *e)
{
	return e->key;
}

const char *dpma_glue_db_entry_data(const struct ast_db_entry *e)
{
	return e->data;
}

/*! Returns an ast_malloc'ed string or NULL. */
char *dpma_glue_db_get(const char *family, const char *key)
{
	char *out = NULL;

	if (ast_db_get_allocated(family, key, &out)) {
		return NULL;
	}
	return out;
}

/* ------------------------------------------------------------------ */
/* Dialplan                                                           */
/* ------------------------------------------------------------------ */

int dpma_glue_add_extension(const char *context, int replace, const char *exten, int priority,
	const char *label, const char *callerid, const char *app, const char *data,
	const char *registrar)
{
	/* ast_add_extension() keeps the registrar pointer (contexts copy theirs). */
	const char *reg = dpma_glue_intern(registrar);

	if (!reg) {
		return -1;
	}
	return ast_add_extension(context, replace, exten, priority, label, callerid, app,
		ast_strdup(S_OR(data, "")), ast_free_ptr, reg);
}

int dpma_glue_context_create(const char *name, const char *registrar)
{
	return ast_context_find_or_create(NULL, NULL, name, registrar) ? 0 : -1;
}

void dpma_glue_context_destroy(const char *name, const char *registrar)
{
	struct ast_context *con = ast_context_find(name);

	if (con) {
		ast_context_destroy(con, registrar);
	}
}

void dpma_glue_context_destroy_registrar(const char *registrar)
{
	ast_context_destroy(NULL, registrar);
}

int dpma_glue_context_exists(const char *name)
{
	return ast_context_find(name) ? 1 : 0;
}

int dpma_glue_remove_extension(const char *context, const char *exten, int priority,
	const char *registrar)
{
	return ast_context_remove_extension(context, exten, priority, registrar);
}

/* ------------------------------------------------------------------ */
/* Config hooks                                                       */
/* ------------------------------------------------------------------ */

/*
 * Config hook callbacks carry no user data, so a fixed number of slots is
 * provided; each slot forwards to Rust with its index.
 */
extern void dpma_rust_config_hook(int slot, struct ast_config *cfg);

#define DPMA_HOOK_SLOT(n) \
	static int dpma_config_hook_##n(struct ast_config *cfg) \
	{ \
		dpma_rust_config_hook(n, cfg); \
		return 0; \
	}

DPMA_HOOK_SLOT(0)
DPMA_HOOK_SLOT(1)
DPMA_HOOK_SLOT(2)
DPMA_HOOK_SLOT(3)
DPMA_HOOK_SLOT(4)
DPMA_HOOK_SLOT(5)
DPMA_HOOK_SLOT(6)
DPMA_HOOK_SLOT(7)

static config_hook_cb dpma_config_hooks[] = {
	dpma_config_hook_0, dpma_config_hook_1, dpma_config_hook_2, dpma_config_hook_3,
	dpma_config_hook_4, dpma_config_hook_5, dpma_config_hook_6, dpma_config_hook_7,
};

int dpma_glue_config_hook_slots(void)
{
	return (int) ARRAY_LEN(dpma_config_hooks);
}

int dpma_glue_config_hook_register(int slot, const char *name, const char *filename,
	const char *module)
{
	if (slot < 0 || slot >= (int) ARRAY_LEN(dpma_config_hooks)) {
		return -1;
	}
	return ast_config_hook_register(name, filename, module, 0, dpma_config_hooks[slot]);
}

/* ------------------------------------------------------------------ */
/* Misc                                                               */
/* ------------------------------------------------------------------ */

struct ast_module *dpma_glue_self(void)
{
	return AST_MODULE_SELF;
}

void dpma_glue_module_ref(void)
{
	ast_module_ref(AST_MODULE_SELF);
}

void dpma_glue_module_unref(void)
{
	ast_module_unref(AST_MODULE_SELF);
}
