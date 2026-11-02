//! Test-only CLI commands, compiled with `--features devtest` and never
//! part of a release build.  They let the test suites under `tests/`
//! exercise each subsystem directly in a test Asterisk (e.g., `dpmadev
//! config <phone>` prints a phone's configuration document).
//!
//! Each subsystem contributes commands from its own `devtest_commands()`,
//! all under the prefix `dpmadev`; this file only aggregates them.

use dpma_ast::cli::{CliArgs, CliCommand, CliResult};

/// `dpmadev proto selftest`: exercise dpma-proto inside Asterisk, in
/// particular its log hook (the bad salt and the URI without a supported
/// scheme log through it to the DPMA level as phone_crypto.c and
/// reqresp_parser.c).
fn proto_selftest(a: &CliArgs) -> CliResult {
    use dpma_proto::{crypto, framing, uri};
    let pass = match crypto::new_common_password() {
        Ok(p) => p,
        Err(e) => {
            a.out(format!("common password: {}\n", e));
            return CliResult::Failure;
        }
    };
    let salt = crypto::new_salt().unwrap_or([0; crypto::SALT_LEN]);
    let body = "x".repeat(1000);
    let chunks = framing::split(body.as_bytes(), framing::COMMAND_PREFIX, framing::UDP_ENCRYPTED_LIMIT, false);
    let ok = framing::encrypt_chunks(&chunks, &pass, &salt).ok().and_then(|b64| {
        let refs: Vec<&[u8]> = b64.iter().map(|s| s.as_bytes()).collect();
        framing::decrypt_chunks(&refs, &pass, crypto::salt_to_hex(&salt)).ok()
    });
    let expected: Vec<u8> = chunks.iter().flat_map(|c| c.plain.clone()).collect();
    a.out(format!("chunks: {}, round trip: {}\n", chunks.len(), if ok == Some(expected) { "ok" } else { "FAILED" }));
    a.out(format!("bad salt: {:?}\n", crypto::salt_from_hex("12G4").err().map(|e| e.message().to_string())));
    let r = uri::parse_uri("tel:+15551234", Some("sip:,sips:"), true, true);
    a.out(format!("tel: URI error: {}\n", r.error));
    CliResult::Success
}

pub fn commands() -> Vec<CliCommand> {
    let mut v = vec![CliCommand {
        command: "dpmadev proto selftest",
        summary: "Exercise dpma-proto (test only)",
        usage: "Usage: dpmadev proto selftest\n",
        exec: proto_selftest,
        complete: None,
    }];
    v.extend(crate::transport::devtest_commands());
    v.extend(crate::session::devtest_commands());
    v.extend(crate::method::devtest_commands());
    v.extend(crate::request::devtest_commands());
    v.extend(crate::auth::devtest_commands());
    v.extend(crate::users::build_config::devtest_commands());
    v.extend(crate::users::runtime::devtest_commands());
    v.extend(crate::method_api::voicemail::devtest_commands());
    v.extend(crate::method_api::calls::devtest_commands());
    v.extend(crate::pjsip::devtest::devtest_commands());
    v.extend(crate::ami::messages::devtest_commands());
    v
}
