//! Generates the raw bindings to Asterisk and pjproject with `bindgen`.
//!
//! This is the one place that knows where the headers are and how to read
//! them.  `ASTERISK_SOURCE_DIR` names a configured Asterisk source tree
//! (22, 23, or 24) built with the bundled pjproject, or a copy of its
//! headers in the same layout:
//!
//! * `<ASTERISK_SOURCE_DIR>/include`: `asterisk.h` and the `asterisk/`
//!   headers, with `autoconfig.h` (written by configure) and `buildopts.h`
//!   (written by make: `make include/asterisk/buildopts.h` after
//!   configure, or any full build);
//! * `<ASTERISK_SOURCE_DIR>/third-party/pjproject/source`: the bundled
//!   pjproject, which configure downloads and configures (its
//!   `pjlib/include`, `pjlib-util/include`, `pjnath/include`,
//!   `pjmedia/include`, and `pjsip/include` are used).  The defines are
//!   those of `PJPROJECT_INCLUDE` in Asterisk's `makeopts`.
//!
//! `cargo xtask headers` copies such headers out of the test image of a
//! pinned release (`/opt/asterisk-headers`, which is `ASTERISK_SOURCE_DIR`
//! in the image).  The bindings follow the headers of the tree, so one
//! source builds against every supported release.
//!
//! Only the functions, types, and constants that dpma-rs uses are
//! generated (the lists below); add to them as needed.  Static inline
//! functions and function-like macros are not generated: `dpma-ast`
//! reimplements the ones dpma-rs needs.  libclang must be installed
//! (bindgen finds it through `LIBCLANG_PATH` or the usual places).

use std::path::PathBuf;

/// The headers read, in this order (`asterisk.h` must come first).
const HEADERS: &[&str] = &[
    "asterisk.h",
    "asterisk/module.h",
    "asterisk/buildopts.h",
    "asterisk/logger.h",
    "asterisk/options.h",
    "asterisk/paths.h",
    "asterisk/utils.h",
    "asterisk/strings.h",
    "asterisk/astobj2.h",
    "asterisk/astdb.h",
    "asterisk/cli.h",
    "asterisk/config.h",
    "asterisk/manager.h",
    "asterisk/message.h",
    "asterisk/pbx.h",
    "asterisk/app.h",
    "asterisk/channel.h",
    "asterisk/callerid.h",
    "asterisk/devicestate.h",
    "asterisk/presencestate.h",
    "asterisk/dial.h",
    "asterisk/sched.h",
    "asterisk/threadpool.h",
    "asterisk/json.h",
    "asterisk/xml.h",
    "asterisk/stasis.h",
    "asterisk/stasis_message_router.h",
    "asterisk/parking.h",
    "asterisk/sorcery.h",
    "pjsip.h",
    "pjsip_ua.h",
    "pjlib.h",
    "pjlib-util.h",
    "asterisk/res_pjsip.h",
    "asterisk/res_pjsip_session.h",
    "asterisk/res_pjsip_pubsub.h",
    "asterisk/res_pjsip_presence_xml.h",
    "asterisk/res_pjsip_body_generator_types.h",
];

/// Functions (exact names).
const FUNCTIONS: &[&str] = &[
    // memory, logging, process
    "__ast_free",
    "__ast_malloc",
    "__ast_calloc",
    "__ast_strdup",
    "ast_free_ptr",
    "ast_log",
    "ast_debug_get_by_module",
    "ast_logger_register_level",
    "ast_logger_unregister_level",
    "ast_module_register",
    "ast_module_unregister",
    "ast_random",
    "ast_register_atexit",
    "ast_unregister_atexit",
    "ast_register_thread",
    "ast_unregister_thread",
    "ast_pthread_create_detached_stack",
    "ast_strip_quoted",
    "ast_xml_escape",
    // configuration
    "ast_config_load2",
    "ast_config_destroy",
    "ast_category_browse",
    "ast_variable_browse",
    "ast_variable_retrieve",
    "_ast_variable_new",
    "ast_variables_destroy",
    "ast_config_hook_register",
    "ast_config_hook_unregister",
    // CLI and manager
    "__ast_cli_register",
    "ast_cli_unregister",
    "ast_cli",
    "ast_manager_register2",
    "ast_manager_unregister",
    "astman_append",
    "astman_get_header",
    "astman_send_ack",
    "astman_send_error",
    "astman_send_listack",
    "__ast_manager_event_multichan",
    "ast_hook_send_action",
    // out of call messages
    "ast_msg_tech_register",
    "ast_msg_tech_unregister",
    "ast_msg_alloc",
    "ast_msg_ref",
    "ast_msg_destroy",
    "ast_msg_set_context",
    "ast_msg_set_exten",
    "ast_msg_set_body",
    "ast_msg_set_var",
    "ast_msg_set_var_outbound",
    "ast_msg_get_var",
    "ast_msg_get_body",
    "ast_msg_get_to",
    "ast_msg_get_from",
    "ast_msg_get_tech",
    "ast_msg_get_endpoint",
    "ast_msg_queue",
    "ast_msg_send",
    "ast_msg_var_iterator_init",
    "ast_msg_var_iterator_next",
    "ast_msg_var_iterator_next_received",
    "ast_msg_var_unref_current",
    "ast_msg_var_iterator_destroy",
    // AstDB
    "ast_db_get_allocated",
    "ast_db_put",
    "ast_db_del",
    "ast_db_gettree",
    "ast_db_freetree",
    // dialplan and applications
    "ast_add_extension",
    "ast_context_find",
    "ast_context_find_or_create",
    "ast_context_destroy",
    "ast_context_remove_extension",
    "pbx_builtin_setvar_helper",
    "pbx_builtin_getvar_helper",
    "ast_register_application2",
    "ast_unregister_application",
    "__ast_app_separate_args",
    "ast_app_parse_options",
    "ast_control_streamfile",
    "ast_control_streamfile_w_cb",
    // astobj2
    "__ao2_alloc",
    "__ao2_ref",
    "__ao2_lock",
    "__ao2_unlock",
    "__ao2_container_alloc_hash",
    "__ao2_link",
    "__ao2_unlink",
    "__ao2_find",
    "__ao2_callback",
    "ao2_iterator_init",
    "__ao2_iterator_next",
    "ao2_iterator_destroy",
    // channels and devices
    "ast_channel_iterator_by_name_new",
    "ast_channel_iterator_all_new",
    "ast_channel_iterator_next",
    "ast_channel_iterator_destroy",
    "ast_channel_get_by_name",
    "ast_channel_tech",
    "ast_channel_tech_pvt",
    "ast_channel_name",
    "ast_channel_uniqueid",
    "ast_channel_state",
    "ast_channel_creationtime",
    "ast_channel_caller",
    "ast_channel_connected",
    "ast_answer",
    "ast_presence_state",
    "ast_presence_state2str",
    "ast_presence_state_val",
    // dialing, scheduling, thread pools
    "ast_dial_create",
    "ast_dial_append",
    "ast_dial_prerun",
    "ast_dial_run",
    "ast_dial_get_channel",
    "ast_dial_set_user_data",
    "ast_dial_get_user_data",
    "ast_dial_option_global_enable",
    "ast_dial_destroy",
    "ast_sched_context_create",
    "ast_sched_context_destroy",
    "ast_sched_start_thread",
    "ast_sched_add",
    "ast_sched_del",
    "ast_sched_runq",
    "ast_sched_when",
    "ast_threadpool_create",
    "__ast_threadpool_push",
    "ast_threadpool_shutdown",
    // JSON and XML
    "ast_json_load_string",
    "ast_json_object_create",
    "ast_json_array_create",
    "ast_json_string_create",
    "ast_json_object_set",
    "ast_json_array_append",
    "ast_json_object_get",
    "ast_json_typeof",
    "ast_json_string_get",
    "ast_json_pack",
    "ast_json_dump_string_format",
    "ast_json_free",
    "ast_json_unref",
    "ast_xml_open",
    "ast_xml_close",
    "ast_xml_get_root",
    "ast_xml_node_get_name",
    "ast_xml_node_get_children",
    "ast_xml_node_get_next",
    "ast_xml_find_element",
    "ast_xml_new_child",
    "ast_xml_set_attribute",
    "ast_xml_get_text",
    "ast_xml_get_attribute",
    "ast_xml_free_attr",
    "ast_xml_free_text",
    "ast_xml_doc_dump_file",
    // Stasis, parking, voicemail
    "stasis_topic_create",
    "stasis_forward_all",
    "stasis_forward_cancel",
    "__stasis_message_router_create",
    "stasis_message_router_add",
    "stasis_message_router_unsubscribe_and_join",
    "stasis_message_data",
    "ast_parking_topic",
    "ast_parked_call_type",
    "ast_vm_mailbox_snapshot_create",
    "ast_vm_mailbox_snapshot_destroy",
    "ast_vm_msg_move",
    "ast_vm_msg_remove",
    "ast_vm_msg_forward",
    "ast_vm_index_to_foldername",
    "ast_vm_msg_play",
    // PJSIP and sorcery
    "ast_sip_get_sorcery",
    "ast_sip_default_outbound_endpoint",
    "ast_sip_for_each_aor",
    "ast_sip_for_each_contact",
    "ast_sip_register_endpoint_identifier",
    "ast_sip_unregister_endpoint_identifier",
    "ast_sip_create_request",
    "ast_sip_add_header",
    "ast_sip_add_body",
    "ast_sip_session_send_request",
    "__ast_sip_push_task_wait_servant",
    "ast_sip_pubsub_register_body_supplement",
    "ast_sip_pubsub_unregister_body_supplement",
    "ast_sip_presence_exten_state_to_str",
    "ast_sip_presence_xml_create_node",
    "ast_sip_presence_xml_create_attr",
    "ast_sip_sanitize_xml",
    "ast_sorcery_alloc",
    "ast_sorcery_object_get_id",
    "ast_sorcery_objectset_create2",
    "ast_sorcery_objectset_apply",
    "ast_sorcery_retrieve_by_id",
    "ast_sorcery_observer_add",
    "ast_sorcery_observer_remove",
    "pj_get_version",
    "pj_strdup2",
    "pj_xml_find_node",
    "pjsip_msg_find_hdr_by_name",
    "pjsip_tx_data_dec_ref",
];

/// Global variables.
const VARS: &[&str] = &[
    "ast_options",
    "option_debug",
    "ast_verb_sys_level",
    "ast_config_AST_VAR_DIR",
    "ast_config_AST_CONFIG_DIR",
    // string and numeric macros (ASTERISK_GPL_KEY: see `gpl_key`)
    "DPMA_SYS_GPL_KEY",
    "AST_MAX_CMD_LEN",
    "PJSIP_MAX_URL_SIZE",
    "AST_PRES_RESTRICTION",
    "AST_PRES_RESTRICTED",
    "CONFIG_FLAG_.*",
    "EVENT_FLAG_.*",
    "AST_THREADPOOL_OPTIONS_VERSION",
    "AST_DIGIT_ANY",
];

/// Types (structures the Rust code reads or builds).  Enums and the types
/// these refer to come along.
const TYPES: &[&str] = &[
    "ast_module_info",
    "ast_module_load_result",
    "ast_module_load_priority",
    "ast_module_flags",
    "ast_module_support_level",
    "ast_option_flags",
    "ast_cli_entry",
    "ast_cli_args",
    "ast_cli_command",
    "ast_msg_tech",
    "ast_variable",
    "ast_db_entry",
    "manager_custom_hook",
    "ao2_iterator",
    "ao2_alloc_opts",
    "ao2_lock_req",
    "ao2_container_opts",
    "search_flags",
    "_cb_results",
    "ast_channel_tech",
    "ast_channel_state",
    "ast_device_state",
    "ast_device_state_info",
    "ast_party_caller",
    "ast_party_connected_line",
    "ast_app_option",
    "ast_threadpool_options",
    "ast_dial_option",
    "ast_dial_result",
    "ast_json_type",
    "ast_json_encoding_format",
    "ast_parked_call_payload",
    "ast_parked_call_event_type",
    "ast_vm_mailbox_snapshot",
    "ast_vm_msg_snapshot",
    "ast_vm_snapshot_sort_val",
    "ast_waitstream_fr_cb_values",
    "config_hook_flags",
    "ast_sorcery_observer",
    "ast_sip_endpoint",
    "ast_sip_contact",
    "ast_sip_contact_wrapper",
    "ast_sip_endpoint_identifier",
    "ast_sip_channel_pvt",
    "ast_sip_session",
    "ast_sip_body",
    "ast_sip_pubsub_body_supplement",
    "ast_sip_exten_state_data",
    "ast_handler_flags",
    "pj_str_t",
    "pj_xml_node",
    "pjsip_rx_data",
];

/// `ASTERISK_GPL_KEY` (module.h) is a string literal continued over
/// several lines with backslash-newlines, which bindgen does not read.
/// This restates it on one line, as `DPMA_SYS_GPL_KEY`, with each
/// backslash-newline removed as the C preprocessor removes them; bindgen
/// reads that, and the crate exports it as `ASTERISK_GPL_KEY`.
fn gpl_key(asterisk: &std::path::Path) -> String {
    let path = asterisk.join("asterisk/module.h");
    println!("cargo:rerun-if-changed={}", path.display());
    let text = std::fs::read_to_string(&path).unwrap_or_default();
    let mut define = String::new();
    let lines = text.lines().skip_while(|l| !l.starts_with("#define ASTERISK_GPL_KEY"));
    for line in lines {
        match line.strip_suffix('\\') {
            Some(start) => define.push_str(start),
            None => {
                define.push_str(line);
                break;
            }
        }
    }
    if define.is_empty() {
        println!("cargo:warning=ASTERISK_GPL_KEY not found in {}", path.display());
        return String::new();
    }
    format!("{}\n", define.replacen("ASTERISK_GPL_KEY", "DPMA_SYS_GPL_KEY", 1))
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=ASTERISK_SOURCE_DIR");

    let source = match std::env::var_os("ASTERISK_SOURCE_DIR") {
        Some(d) if !d.is_empty() => PathBuf::from(d),
        _ => panic!(
            "ASTERISK_SOURCE_DIR is not set: set it to a configured Asterisk source tree \
             (see README.md, \"Building\")"
        ),
    };
    let asterisk = source.join("include");
    for header in ["asterisk.h", "asterisk/autoconfig.h", "asterisk/buildopts.h"] {
        if !asterisk.join(header).exists() {
            panic!(
                "{} not found: ASTERISK_SOURCE_DIR={} must be a configured Asterisk source tree \
                 (./configure, then make include/asterisk/buildopts.h)",
                asterisk.join(header).display(),
                source.display()
            );
        }
    }
    let pjproject = source.join("third-party/pjproject/source");
    if !pjproject.join("pjlib/include/pj/config_site.h").exists() {
        panic!(
            "the bundled pjproject is not configured in {} (configure Asterisk with \
             --with-pjproject-bundled)",
            pjproject.display()
        );
    }
    let mut includes = vec![asterisk];
    for s in ["pjlib", "pjlib-util", "pjnath", "pjmedia", "pjsip"] {
        includes.push(pjproject.join(s).join("include"));
    }

    let mut header: String = HEADERS.iter().map(|h| format!("#include \"{}\"\n", h)).collect();
    header.push_str(&gpl_key(&includes[0]));
    let mut builder = bindgen::Builder::default()
        .header_contents("dpma_sys.h", &header)
        // A module, as far as the headers are concerned, but without a
        // module name: AST_MODULE_SELF is never used here.
        .clang_args(["-D_GNU_SOURCE", "-D_REENTRANT", "-DAST_NOT_MODULE"])
        // utils.h declares RAII_VAR with blocks when compiled with clang.
        .clang_arg("-fblocks")
        // PJPROJECT_INCLUDE in Asterisk's makeopts.
        .clang_args([
            "-DPJ_AUTOCONF=1",
            "-DPJ_HAS_LINUX_EPOLL=1",
            "-DPJ_IS_BIG_ENDIAN=0",
            "-DPJ_IS_LITTLE_ENDIAN=1",
            "-DPJMEDIA_HAS_SRTP=0",
        ])
        .clang_args(includes.iter().map(|i| format!("-I{}", i.display())))
        .ctypes_prefix("::std::os::raw")
        .default_enum_style(bindgen::EnumVariation::Consts)
        .prepend_enum_name(false)
        .generate_comments(false)
        .layout_tests(true)
        .derive_default(false)
        .derive_debug(false)
        .derive_copy(true)
        .size_t_is_usize(true)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()));
    for f in FUNCTIONS {
        builder = builder.allowlist_function(format!("^{}$", f));
    }
    for v in VARS {
        builder = builder.allowlist_var(format!("^{}$", v));
    }
    for t in TYPES {
        builder = builder.allowlist_type(format!("^{}$", t));
    }
    let bindings = builder.generate().expect("unable to generate the Asterisk bindings");
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("bindings.rs");
    bindings.write_to_file(out).expect("unable to write the Asterisk bindings");
}
