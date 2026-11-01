//! Raw declarations of the C glue and of the Asterisk functions that are
//! called directly.

use crate::types::*;
use std::os::raw::{c_char, c_int, c_uint, c_void};

extern "C" {
    // ---- glue: logging / misc ----
    pub fn dpma_glue_log(level: c_int, file: *const c_char, line: c_int, func: *const c_char, msg: *const c_char);
    pub fn dpma_glue_debug_atleast(level: c_int) -> c_int;
    pub fn dpma_glue_verbose_atleast(level: c_int) -> c_int;
    pub fn dpma_glue_fully_booted() -> c_int;
    pub fn dpma_glue_var_dir() -> *const c_char;
    pub fn dpma_glue_config_dir() -> *const c_char;
    pub fn dpma_glue_free(ptr: *mut c_void);
    pub fn dpma_glue_strdup(s: *const c_char) -> *mut c_char;
    pub fn dpma_glue_self() -> *mut AstModule;
    pub fn dpma_glue_module_ref();
    pub fn dpma_glue_module_unref();

    // ---- glue: config ----
    pub fn dpma_glue_config_load(filename: *const c_char, who: *const c_char, flags: c_uint) -> *mut AstConfig;
    pub fn dpma_glue_config_status(cfg: *const AstConfig) -> c_int;
    pub fn dpma_glue_variable_name(v: *const AstVariable) -> *const c_char;
    pub fn dpma_glue_variable_value(v: *const AstVariable) -> *const c_char;
    pub fn dpma_glue_variable_lineno(v: *const AstVariable) -> c_int;
    pub fn dpma_glue_variable_next(v: *const AstVariable) -> *const AstVariable;

    // ---- glue: CLI ----
    pub fn dpma_glue_cli_register(
        commands: *const *const c_char,
        summaries: *const *const c_char,
        usages: *const *const c_char,
        ids: *const c_int,
        count: c_int,
    ) -> *mut c_void;
    pub fn dpma_glue_cli_unregister(handle: *mut c_void);
    pub fn dpma_glue_cli_out(fd: c_int, text: *const c_char);

    // ---- glue: manager ----
    pub fn dpma_glue_manager_register(action: *const c_char, authority: c_int, synopsis: *const c_char, description: *const c_char) -> c_int;
    pub fn dpma_glue_manager_unregister(action: *const c_char);
    pub fn dpma_glue_astman_append(s: *mut Mansession, text: *const c_char);
    pub fn dpma_glue_manager_event(category: c_int, event: *const c_char, body: *const c_char);
    pub fn dpma_glue_eventflag_system() -> c_int;
    pub fn dpma_glue_eventflag_config() -> c_int;
    pub fn dpma_glue_eventflag_reporting() -> c_int;
    pub fn dpma_glue_manager_hook_action(action_text: *const c_char) -> *mut c_char;

    // ---- glue: messaging ----
    pub fn dpma_glue_msg_tech_register() -> c_int;
    pub fn dpma_glue_msg_tech_unregister() -> c_int;
    pub fn dpma_glue_msg_set_context(msg: *mut AstMsg, value: *const c_char) -> c_int;
    pub fn dpma_glue_msg_set_exten(msg: *mut AstMsg, value: *const c_char) -> c_int;
    pub fn dpma_glue_msg_set_body(msg: *mut AstMsg, value: *const c_char) -> c_int;
    pub fn dpma_glue_msg_set_from(msg: *mut AstMsg, value: *const c_char) -> c_int;
    pub fn dpma_glue_msg_set_to(msg: *mut AstMsg, value: *const c_char) -> c_int;
    pub fn dpma_glue_msg_ref(msg: *const AstMsg) -> *mut AstMsg;

    // ---- glue: astdb ----
    pub fn dpma_glue_db_entry_next(e: *const AstDbEntry) -> *const AstDbEntry;
    pub fn dpma_glue_db_entry_key(e: *const AstDbEntry) -> *const c_char;
    pub fn dpma_glue_db_entry_data(e: *const AstDbEntry) -> *const c_char;
    pub fn dpma_glue_db_get(family: *const c_char, key: *const c_char) -> *mut c_char;

    // ---- glue: dialplan ----
    pub fn dpma_glue_add_extension(
        context: *const c_char,
        replace: c_int,
        exten: *const c_char,
        priority: c_int,
        label: *const c_char,
        callerid: *const c_char,
        app: *const c_char,
        data: *const c_char,
        registrar: *const c_char,
    ) -> c_int;
    pub fn dpma_glue_context_create(name: *const c_char, registrar: *const c_char) -> c_int;
    pub fn dpma_glue_context_destroy(name: *const c_char, registrar: *const c_char);
    pub fn dpma_glue_context_exists(name: *const c_char) -> c_int;
    pub fn dpma_glue_context_destroy_registrar(registrar: *const c_char);

    // ---- glue: config hooks ----
    pub fn dpma_glue_config_hook_slots() -> c_int;
    pub fn dpma_glue_config_hook_register(slot: c_int, name: *const c_char, filename: *const c_char, module: *const c_char) -> c_int;
    pub fn ast_config_hook_unregister(name: *const c_char);
    pub fn dpma_glue_remove_extension(context: *const c_char, exten: *const c_char, priority: c_int, registrar: *const c_char) -> c_int;

    // ---- Asterisk core, called directly ----
    pub fn ast_logger_register_level(name: *const c_char) -> c_int;
    pub fn ast_logger_unregister_level(name: *const c_char);
    pub fn ast_category_browse(cfg: *mut AstConfig, prev: *const c_char) -> *mut c_char;
    pub fn ast_variable_browse(cfg: *const AstConfig, category: *const c_char) -> *const AstVariable;
    pub fn ast_variable_retrieve(cfg: *mut AstConfig, category: *const c_char, variable: *const c_char) -> *const c_char;
    pub fn ast_config_destroy(cfg: *mut AstConfig);

    pub fn astman_get_header(m: *const Message, var: *const c_char) -> *const c_char;
    pub fn astman_send_ack(s: *mut Mansession, m: *const Message, msg: *const c_char);
    pub fn astman_send_error(s: *mut Mansession, m: *const Message, error: *const c_char);
    pub fn astman_send_listack(s: *mut Mansession, m: *const Message, msg: *const c_char, listflag: *const c_char);

    pub fn ast_msg_alloc() -> *mut AstMsg;
    pub fn ast_msg_destroy(msg: *mut AstMsg) -> *mut AstMsg;
    pub fn ast_msg_set_var(msg: *mut AstMsg, name: *const c_char, value: *const c_char) -> c_int;
    pub fn ast_msg_set_var_outbound(msg: *mut AstMsg, name: *const c_char, value: *const c_char) -> c_int;
    pub fn ast_msg_get_var(msg: *mut AstMsg, name: *const c_char) -> *const c_char;
    pub fn ast_msg_get_body(msg: *const AstMsg) -> *const c_char;
    pub fn ast_msg_queue(msg: *mut AstMsg) -> c_int;
    pub fn ast_msg_send(msg: *mut AstMsg, to: *const c_char, from: *const c_char) -> c_int;

    pub fn ast_db_put(family: *const c_char, key: *const c_char, value: *const c_char) -> c_int;
    pub fn ast_db_del(family: *const c_char, key: *const c_char) -> c_int;
    pub fn ast_db_gettree(family: *const c_char, keytree: *const c_char) -> *mut AstDbEntry;
    pub fn ast_db_freetree(dbe: *mut AstDbEntry);

    pub fn ast_presence_state(provider: *const c_char, subtype: *mut *mut c_char, message: *mut *mut c_char) -> c_int;
    pub fn ast_presence_state2str(state: c_int) -> *const c_char;
    pub fn ast_presence_state_val(val: *const c_char) -> c_int;
    pub fn pbx_builtin_setvar_helper(chan: *mut AstChannel, name: *const c_char, value: *const c_char) -> c_int;
}
