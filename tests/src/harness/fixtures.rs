//! Fixtures several suites share: preparing the instance, the simulator's
//! test PKI and configuration, simulated phones, sessions and incidents as
//! the CLI and AMI show them, and the documents the module builds.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use bstr::{BString, ByteSlice};
use serde_json::json;

use super::conf::ConfFile;
use super::instance::Instance;
use crate::ami::{AmiClient, AmiMessage};
use crate::mkpki;
use crate::sim::{self, Phone};

/// The global pin of the scratch configuration and the test setups.
pub const GLOBALPIN: &str = "344486";

/// The simulator's default phone (`res_digium_phone_sim.conf`): name,
/// MAC, pin, and line.
pub const SIMPHONE: (&str, &str, &str, &str) = ("simphone", "000fd3000001", "1234", "1001");
/// The second test phone.
pub const SIMPHONE2: (&str, &str, &str, &str) = ("simphone2", "000fd3000002", "5678", "1002");

/// The module's devtest build, which the suites need.
pub const DEVTEST_HINT: &str = "cargo build -p res_dpma_rs --features devtest";

/// The simulator's test configuration snippets: the file name in the
/// instance, the configuration file that includes it, and the contents
/// (`@SIP_PORT@` is replaced).
///
/// - `pjsip_dpma_sim.conf`: a TCP transport on the instance's SIP port;
///   the endpoint `dpma-sim` with
///   `message_context=dpma_pjsip_message_context`, identified by
///   `match=127.0.0.1` (a test-only stand-in for the module's endpoint
///   identifier); and `dpma-sim-loopback`, identified by
///   `match=127.0.0.2`, whose messages go to a static test context.  With
///   the module loaded, the simulator's MESSAGEs (which carry
///   `X-Digium-User-Agent`) are identified by the module's endpoint
///   identifier instead, and the `dpma-sim` identify is not needed; take
///   the snippet out ([`remove_sim_conf`]) when testing other PJSIP
///   clients: it matches every request from 127.0.0.1, REGISTERs
///   included.  The loopback path needs `--no-digium-ua-header` while the
///   module is loaded.
/// - `extensions_dpma_sim.conf`: `[dpma-sim-loopback]` logs every MESSAGE
///   from 127.0.0.2 with its AppServer headers and answers Echo the way
///   the module's `handle_request_echo` does (no module needed);
///   `[dpma-sim-send]` sends an unencrypted `digium.config.update` event
///   to a listening simulator: `channel originate
///   Local/<port>@dpma-sim-send application Wait 1`.
/// - `res_digium_phone_sim.conf`: the test phones [`SIMPHONE`] (MAC
///   `000fd3000001`, the simulator's default; pin 1234; line 1001, the
///   PJSIP endpoint 1001 with secret `secret1001`) and [`SIMPHONE2`] (MAC
///   `000fd3000002`; pin 5678; line 1002, secret `secret1002`).
///
/// The scratch configuration's `[general]` has `globalpin=344486`
/// ([`GLOBALPIN`]), `config_auth=mac_globalpin`, and
/// `userlist_auth=disabled`; change them in the instance for the other
/// authentication modes.
pub const SIM_CONF: [(&str, &str, &str); 3] = [
    (
        "pjsip_dpma_sim.conf",
        "pjsip.conf",
        include_str!("../../data/sim-conf/pjsip_dpma_sim.conf"),
    ),
    (
        "extensions_dpma_sim.conf",
        "extensions.conf",
        include_str!("../../data/sim-conf/extensions_dpma_sim.conf"),
    ),
    (
        "res_digium_phone_sim.conf",
        "res_digium_phone.conf",
        include_str!("../../data/sim-conf/res_digium_phone_sim.conf"),
    ),
];

/// Prepares the instance for a suite: stops Asterisk, resets the
/// configuration, runs `setup`, installs the module (debug build), starts
/// Asterisk, and checks that the module is a devtest build.
pub fn prepare(inst: &Instance, setup: impl FnOnce(&Instance) -> Result<()>) -> Result<()> {
    inst.stop()?;
    inst.reset_conf()?;
    setup(inst)?;
    use_test_trust(inst)?;
    inst.install("debug")?;
    inst.start()?;
    check_devtest(inst)
}

/// The module defaults to the certificates embedded in the original, so a
/// suite that installed the test PKI must point `phone_ca_file` and
/// `appserver_certificate` at it, in `[general]` itself: the module, as
/// the original, reads the first `[general]` only.
fn use_test_trust(inst: &Instance) -> Result<()> {
    let dpma = inst.etc.join("dpma");
    let ca = dpma.join("phone_ca.pem");
    if !ca.exists() {
        return Ok(());
    }
    let appserver = dpma.join("appserver.pem");
    let (ca, appserver) = (ca.to_string_lossy(), appserver.to_string_lossy());
    ConfFile::new(&inst.conf("res_digium_phone.conf")).set_options(
        "general",
        &[
            ("phone_ca_file", Some(ca.as_bytes())),
            ("appserver_certificate", Some(appserver.as_bytes())),
        ],
    )
}

/// Fails unless the running module has the `dpmadev` CLI commands.
pub fn check_devtest(inst: &Instance) -> Result<()> {
    let out = inst.cli_run("module show like res_dpma_rs.so")?;
    if !out.contains_str("res_dpma_rs.so") || out.contains_str("0 modules loaded") {
        bail!("res_dpma_rs.so is not loaded:\n{out}");
    }
    let out = inst.cli_run("dpmadev session prune")?;
    if out.contains_str("No such command") {
        bail!("the installed module is not a devtest build (build it: {DEVTEST_HINT})");
    }
    Ok(())
}

/// The simulator setup: the test PKI ([`install_sim_pki`]) and the test
/// configuration ([`install_sim_conf`]).
pub fn sim_setup(inst: &Instance) -> Result<()> {
    install_sim_pki(inst)?;
    install_sim_conf(inst)
}

/// Makes the test PKI if needed (in [`sim::default_pki_dir`]) and installs
/// its trust material into the instance.
pub fn install_sim_pki(inst: &Instance) -> Result<()> {
    let dir = sim::default_pki_dir();
    mkpki::Generator::new(&dir).quiet().generate()?;
    mkpki::install(&dir, &inst.etc, true)
}

/// Installs the simulator's test configuration into the instance (the
/// SIP port filled in) and includes it from `pjsip.conf`,
/// `extensions.conf`, and `res_digium_phone.conf`.  Reload or restart
/// Asterisk afterwards.
pub fn install_sim_conf(inst: &Instance) -> Result<()> {
    for (snippet, main, text) in SIM_CONF {
        let text = text.replace("@SIP_PORT@", &inst.sip_port.to_string());
        let dest = inst.conf(snippet);
        let tmp = inst.conf(&format!("{snippet}.new"));
        std::fs::write(&tmp, text)?;
        std::fs::rename(&tmp, &dest).with_context(|| dest.display().to_string())?;
        ConfFile::new(&inst.conf(main)).add_include(snippet)?;
    }
    Ok(())
}

/// Takes the simulator's test configuration out of the instance.
pub fn remove_sim_conf(inst: &Instance) -> Result<()> {
    for (snippet, main, _) in SIM_CONF {
        ConfFile::new(&inst.conf(main)).remove_include(snippet)?;
        let _ = std::fs::remove_file(inst.conf(snippet));
    }
    Ok(())
}

/// Starts a phone and handshakes; fails when the handshake does.
pub fn phone(opts: sim::Options) -> Result<Phone> {
    let p = Phone::start(opts)?;
    let ex = p.handshake().send()?;
    if !ex.ok() {
        bail!("handshake failed:\n{}", ex.describe(0));
    }
    Ok(p)
}

/// A phone with a session and a configuration token for `user` (an
/// authenticated session is never pruned).
pub fn phone_with_token(opts: sim::Options, user: &str, config_password: &str) -> Result<Phone> {
    let p = phone(opts)?;
    let ex = p
        .get_token()
        .user(user)
        .config_password(config_password)
        .send()?;
    if !ex.ok() {
        bail!("token failed:\n{}", ex.describe(0));
    }
    Ok(p)
}

/// The line of `digium_phones show sessions` for session `sid`.
pub fn session_line(inst: &Instance, sid: &str) -> Option<String> {
    let out = inst.cli_text("digium_phones show sessions");
    out.lines()
        .find(|l| l.starts_with(&format!("SessionID:{sid} ")))
        .map(str::to_string)
}

/// The `Auth`, `Inactive`, and `Configured` flags of session `sid` as
/// `digium_phones show sessions` shows them (`"Yes"` or `"No"`).
pub fn session_flags(inst: &Instance, sid: &str) -> Option<(String, String, String)> {
    let line = session_line(inst, sid)?;
    let get = |key: &str| {
        let i = line.find(key)? + key.len();
        Some(line[i..].split_whitespace().next()?.to_string())
    };
    Some((get("Auth:")?, get("Inactive:")?, get("Configured:")?))
}

/// The auth incidents by IP address (`DPMAShowIncidents`).
pub fn incidents(ami: &AmiClient) -> BTreeMap<BString, AmiMessage> {
    ami.action("DPMAShowIncidents", std::iter::empty::<(&str, &str)>())
        .events
        .into_iter()
        .filter(|e| e.get("Event").is_some_and(|v| v == "DPMAShowIncidentsList"))
        .filter_map(|e| Some((e.get("IPAddress")?.clone(), e)))
        .collect()
}

/// Removes every auth incident.
pub fn clear_incidents(ami: &AmiClient) {
    for ip in incidents(ami).into_keys() {
        ami.action("DPMARemoveIncident", [(&b"IPAddress"[..], ip.as_slice())]);
    }
}

/// The wrapper around HTTPRequest and AsteriskResponse documents.
pub const HTTP_PREAMBLE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\n\r\n";

/// A document as the module wraps it for HTTP: the preamble, the
/// document, and a blank line (just the preamble for an empty document).
pub fn http_wrap(doc: &[u8]) -> Vec<u8> {
    let mut out = HTTP_PREAMBLE.to_vec();
    if !doc.is_empty() {
        out.extend_from_slice(doc);
        out.extend_from_slice(b"\r\n\r\n");
    }
    out
}

/// The texts of the request error codes (`phone_request.c`).
pub fn request_error_text(code: u32) -> &'static str {
    match code {
        10001 => "Your request was empty",
        10002 => "Error parsing request",
        10003 => "Missing method name",
        10005 => "Method not found",
        10011 => "Parameters not found",
        10012 => "Call to phone event application failed to complete",
        27168 => "Your account is not permitted to run this action",
        64125 => "Invalid mailbox folder",
        99999 => "Authentication failed for this request",
        _ => "Unknown error",
    }
}

/// A JSON request error document (compact, as the module writes it).
pub fn json_error(method: &str, code: u32, detail: &str) -> String {
    let doc = json!({"response": {"method": method, "errors": {"error": {
        "code": code, "message": format!("{}: {detail} ", request_error_text(code))}}}});
    crate::util::json_compact(&doc)
}

/// An XML request error document.
pub fn xml_error(method: &str, code: u32) -> String {
    format!(
        "<response method=\"{method}\">\r\n<errors>\r\n<error code=\"{code}\" message=\"{}\" />\r\n</errors>\r\n</response>\r\n",
        request_error_text(code)
    )
}

/// The module's hash of a configuration token text (djb2, `h*33 ^ c`,
/// masked to 31 bits; `"blah"` for an empty text).
pub fn token_hash(s: &[u8]) -> u32 {
    let s: &[u8] = if s.is_empty() { b"blah" } else { s };
    let mut h: u32 = 5381;
    for &c in s {
        h = h.wrapping_mul(33) ^ u32::from(c);
    }
    h & 0x7fff_ffff
}

/// Escapes text for the Asterisk CLI parser (backslashes, double quotes,
/// and spaces).
pub fn cli_quote(text: &str) -> String {
    text.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace(' ', "\\ ")
}

/// Escapes an AMI `Variable` value (commas separate variables unless
/// escaped).
pub fn ami_var_escape(text: &str) -> String {
    text.replace('\\', "\\\\").replace(',', "\\,")
}

/// A temporary directory (in `$TMPDIR`), removed when dropped.
pub struct TempDir {
    path: std::path::PathBuf,
}

impl TempDir {
    /// Creates `<tmp>/<prefix>.<pid>.<random>`.
    pub fn new(prefix: &str) -> Result<TempDir> {
        let path = std::env::temp_dir().join(format!(
            "{prefix}.{}.{}",
            std::process::id(),
            crate::util::token_hex(4)
        ));
        std::fs::create_dir_all(&path)?;
        Ok(TempDir { path })
    }

    /// The directory.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Sleeps `secs` seconds.
pub fn sleep(secs: f64) {
    std::thread::sleep(Duration::from_secs_f64(secs));
}
