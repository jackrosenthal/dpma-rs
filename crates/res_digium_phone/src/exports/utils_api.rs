//! phone_utils.c exports (`phone_utils_*`, `dpma_asprintf`,
//! 0x1731a0..0x173a80).  `phone_utils_parse_uri` and
//! `phone_utils_verify_user_agent` are imported by the PJSIP helper (H).
//!
//! ```c
//! char *phone_utils_xml_escape(const char *in, ...);
//! ... phone_utils_xml_find / xml_add / xml_add_doc / xml_add_file ...
//! char *phone_utils_filename_to_fullpath(const char *name, ...);
//! char *phone_utils_shell_quoted(const char *in);
//! void  phone_utils_parse_uri(char *uri, char **addr, char **transport); // H
//! int   phone_utils_str_to_uint(const char *s, unsigned int *out);
//! int   phone_utils_verify_user_agent(const char *ua);                  // H
//! const char *phone_utils_get_model(const char *ua);
//! int   dpma_asprintf(char **ret, const char *fmt, ...);
//! ```
//!
//! Exact parameter lists are in the decompile; P6 confirms them.
//!
//! Owner: P6 "exports" (wave 1).
