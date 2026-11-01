//! phone_users.c exports used by the PJSIP helper module (H) and the rest
//! of the original export list.  `struct phone_line *` and
//! `struct phone_user *` are ao2 handle objects that name a line or phone
//! in `users::Registry`.
//!
//! Prototypes (from the decompile):
//!
//! ```c
//! struct ao2_container *phone_users_get_lines(void);                 // H, no ref
//! const char *phone_users_line_get_name(struct phone_line *);       // H, == line
//! const char *phone_users_line_get_pjsip_auth(struct phone_line *); // H
//! void phone_users_line_set_delme(struct phone_line *, int);        // H
//! int  phone_users_set_line_option(const char *opt, const char *val,
//!                                  struct phone_line *);            // H
//! void phone_users_process_line(struct phone_line *);               // H
//! int  phone_users_process_phone_config(const char *trigger);       // H
//! struct phone_line *phone_line_find(const char *name);             // H, ref
//! struct phone_line *phone_line_find_authenticated(const char *,
//!                                                  const char *);
//! struct phone_user *phone_line_get_user(...);
//! char *phone_line_create(const char *name, int external);
//! int  phone_line_destroy(struct phone_line *);
//! void phone_line_link(struct phone_line *);
//! void phone_line_unlink(struct phone_line *);
//! struct phone_user *phone_user_find(const char *name);             // H, ref
//! void phone_user_token_set_last_info(struct phone_user *,
//!         const char *uri, const char *session, const char *mac);   // H
//! int  phone_users_load(const char *file);
//! int  phone_users_reload(const char *file);
//! int  phone_users_unload(void);
//! int  phone_users_load_tests(void);    // returns 0
//! int  phone_users_unload_tests(void);  // returns 0
//! extern const char *phone_line_transport_option[4]; // "", ";transport=udp", ...
//! extern const char *phone_line_transport_string[4]; // "udp", "udp", "tcp", "tls"
//! extern const char *phone_line_transport_type[4];   // "", "udp", "tcp", "tls"
//! ```
//!
//! Owner: P6 "exports" (wave 1).
