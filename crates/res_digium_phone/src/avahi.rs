//! mDNS/DNS-SD announcement of the configuration server through Avahi
//! (phone_avahi.c): service type `_digiumproxy._udp`, TXT records
//! `serviceType=asterisk` and `sipUrl=sip:proxy@<addr>:<port>[;transport=..]`.
//!
//! Owner: P14 "apps-discovery" (wave 3).  Link libavahi-client with a
//! `#[link(name = "avahi-client")]` attribute on this module's extern
//! block (the original depends on libavahi-client.so.3).

/// `avahi_start` (FUN_00174170).
pub fn start() {}

/// `avahi_stop` (FUN_001742f0).
pub fn stop() {}

/// `avahi_reload` (FUN_00174390).
pub fn reload() {}
