//! The raw-bytes test configuration: text in Latin-1 (bytes that are not
//! UTF-8) in every kind of user-visible field, plus a phone whose texts
//! are UTF-8 with non-ASCII characters (the Rust form of
//! `tests/raw-bytes/fixtures.py`).

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

use anyhow::{Context, Result};
use dpma_tests::harness::Instance;

pub const GLOBALPIN: &[u8] = b"344486";

// The Latin-1 phone (the simulator's MAC) and its line.
pub const PHONE: &[u8] = b"t\xe9l\xe9phone";
pub const MAC: &str = "000fd3001801";
pub const PIN: &[u8] = b"4321";
pub const GROUP_PIN: &[u8] = b"222";
pub const FULL_NAME: &[u8] = b"Jos\xe9 M\xfcller";
pub const LINE: &[u8] = b"1001";
pub const LINE_LABEL: &[u8] = b"L\xednea \xe9";
pub const FIRST_NAME: &[u8] = b"Jos\xe9";
pub const LAST_NAME: &[u8] = b"M\xfcller";
pub const CALLERID: &[u8] = b"\"Jos\xe9\" <1001>";
pub const LOCATION: &[u8] = b"Bureau \xe0 Gen\xe8ve";
pub const IDLE_TEXT: &[u8] = b"Soci\xe9t\xe9 G\xe9n\xe9rale";
pub const CONTACT_FILE: &[u8] = b"contacts-\xe9.xml";
pub const CONTACT_XML: &[u8] = b"<contacts group_name=\"Coll\xe8gues\" editable=\"0\">\n<contact first_name=\"Ren\xe9\" />\n</contacts>\n";
pub const RULES_FILE: &[u8] = b"r\xe8gles.xml";
pub const RULES_XML: &[u8] = b"<display_rules />\n";

pub const NETWORK: &[u8] = b"r\xe9seau";
pub const NET_ALIAS: &[u8] = b"R\xe9seau principal";
pub const FILE_URL: &[u8] = b"http://example.invalid/fichiers-\xe9/";
pub const STATUS_APP: &[u8] = b"statut\xe9";
pub const SUBSTATUS: &[u8] = b"D\xe9jeuner";
pub const CUSTOM_APP: &[u8] = b"perso\xe9";
pub const CUSTOM_NAME: &[u8] = b"Appli\xe9";
pub const VM_APP: &[u8] = b"messagerie\xe9";
pub const TRANSLATION: &[u8] = b"fran\xe7ais";
pub const INBOX_FR: &[u8] = b"Bo\xeete de r\xe9ception";
pub const ALERT: &[u8] = b"alerte\xe9";
pub const ALERT_INFO: &[u8] = b"info-\xe9";
pub const PAGE: &[u8] = b"page\xe9";
pub const PAGE_ALIAS: &[u8] = b"Annonce g\xe9n\xe9rale";
pub const RINGTONE: &[u8] = b"sonnerie\xe9";
pub const RINGTONE_ALIAS: &[u8] = b"M\xe9lodie";

// The UTF-8 phone (a second simulator MAC) and its line.
pub const U_PHONE: &[u8] = "téléphone-utf8".as_bytes();
pub const U_MAC: &str = "000fd3001802";
pub const U_PIN: &[u8] = b"8765";
pub const U_GROUP_PIN: &[u8] = b"111";
pub const U_FULL_NAME: &[u8] = "Zoë Ünal".as_bytes();
pub const U_LINE: &[u8] = b"1002";
pub const U_LINE_LABEL: &str = "Línea ü";
pub const U_NETWORK: &[u8] = "réseau-ü".as_bytes();

// What the simulator sends.
pub const USER_AGENT: &[u8] = b"Digium D65 2_9_17 r\xe9v";
pub const ORIGINATION: &[u8] = b"r\xe9seau-\xe9tage";

/// A voicemail message: folder, message id, caller id, and origtime.
pub struct VmMessage {
    pub folder: &'static str,
    pub msg_id: &'static str,
    pub callerid: &'static [u8],
    pub origtime: u64,
}

// Voicemail (mailbox 1001@default, the Latin-1 phone's line): a message
// with a Latin-1 caller id in Work, one with a UTF-8 caller id in Family.
// (The phone's translation shows INBOX in Latin-1.)
pub const VM_LATIN1: VmMessage = VmMessage {
    folder: "Work",
    msg_id: "1640995200-00000001",
    callerid: b"\"Fran\xe7ois\" <200>",
    origtime: 1640995200,
};
pub const VM_UTF8: VmMessage = VmMessage {
    folder: "Family",
    msg_id: "1640995300-00000002",
    callerid: "\"Frédéric\" <300>".as_bytes(),
    origtime: 1640995300,
};

fn join(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

/// `res_digium_phone.conf`.
pub fn conf() -> Vec<u8> {
    let lines: Vec<Vec<u8>> = vec![
        b"; dpma-rs raw-bytes test (tests/suites/raw-bytes): Latin-1 text".to_vec(),
        b"[general]".to_vec(),
        join(&[b"globalpin=", GLOBALPIN]),
        b"userlist_auth=globalpin".to_vec(),
        b"config_auth=mac".to_vec(),
        b"service_discovery_enabled=no".to_vec(),
        b"".to_vec(),
        join(&[b"[", PHONE, b"]"]),
        b"type=phone".to_vec(),
        join(&[b"mac=", MAC.as_bytes()]),
        join(&[b"pin=", PIN]),
        join(&[b"group_pin=", GROUP_PIN]),
        join(&[b"full_name=", FULL_NAME]),
        join(&[b"line=", LINE]),
        join(&[b"network=", NETWORK]),
        join(&[b"application=", STATUS_APP]),
        join(&[b"application=", CUSTOM_APP]),
        join(&[b"application=", VM_APP]),
        join(&[b"contact=", CONTACT_FILE]),
        join(&[b"alert=", ALERT]),
        join(&[b"multicastpage=", PAGE]),
        join(&[b"ringtone=", RINGTONE]),
        join(&[b"idle_company_text=", IDLE_TEXT]),
        join(&[b"contacts_display_rules=", RULES_FILE]),
        b"".to_vec(),
        join(&[b"[", U_PHONE, b"]"]),
        b"type=phone".to_vec(),
        join(&[b"mac=", U_MAC.as_bytes()]),
        join(&[b"pin=", U_PIN]),
        join(&[b"group_pin=", U_GROUP_PIN]),
        join(&[b"full_name=", U_FULL_NAME]),
        join(&[b"line=", U_LINE]),
        join(&[b"network=", U_NETWORK]),
        join(&[b"contacts_display_rules=", RULES_FILE]),
        b"".to_vec(),
        join(&[b"[", LINE, b"]"]),
        b"type=line".to_vec(),
        b"mailbox=1001@default".to_vec(),
        join(&[b"line_label=", LINE_LABEL]),
        join(&[b"first_name=", FIRST_NAME]),
        join(&[b"last_name=", LAST_NAME]),
        join(&[b"callerid=", CALLERID]),
        join(&[b"location=", LOCATION]),
        b"".to_vec(),
        join(&[b"[", U_LINE, b"]"]),
        b"type=line".to_vec(),
        join(&[b"line_label=", U_LINE_LABEL.as_bytes()]),
        b"".to_vec(),
        join(&[b"[", NETWORK, b"]"]),
        b"type=network".to_vec(),
        join(&[b"alias=", NET_ALIAS]),
        b"cidr=0.0.0.0/0".to_vec(),
        b"registration_address=127.0.0.1".to_vec(),
        join(&[b"file_url_prefix=", FILE_URL]),
        b"".to_vec(),
        join(&[b"[", U_NETWORK, b"]"]),
        b"type=network".to_vec(),
        join(&[b"alias=", "Réseau ü".as_bytes()]),
        b"cidr=0.0.0.0/0".to_vec(),
        b"registration_address=127.0.0.1".to_vec(),
        b"".to_vec(),
        join(&[b"[", STATUS_APP, b"]"]),
        b"type=application".to_vec(),
        b"application=status".to_vec(),
        b"status=away".to_vec(),
        join(&[b"substatus=", SUBSTATUS]),
        b"".to_vec(),
        join(&[b"[", CUSTOM_APP, b"]"]),
        b"type=application".to_vec(),
        b"application=custom".to_vec(),
        join(&[b"name=", CUSTOM_NAME]),
        b"filename=appli.zip".to_vec(),
        b"idlescreen_softkey=yes".to_vec(),
        b"".to_vec(),
        join(&[b"[", VM_APP, b"]"]),
        b"type=application".to_vec(),
        b"application=voicemail".to_vec(),
        join(&[b"translation=", TRANSLATION]),
        b"".to_vec(),
        join(&[b"[", TRANSLATION, b"]"]),
        b"type=translation".to_vec(),
        join(&[b"INBOX=", INBOX_FR]),
        b"".to_vec(),
        join(&[b"[", ALERT, b"]"]),
        b"type=alert".to_vec(),
        join(&[b"alert_info=", ALERT_INFO]),
        b"ring_type=normal".to_vec(),
        b"ringtone=Digium".to_vec(),
        b"".to_vec(),
        join(&[b"[", PAGE, b"]"]),
        b"type=multicastpage".to_vec(),
        join(&[b"alias=", PAGE_ALIAS]),
        b"address=224.0.1.116".to_vec(),
        b"port=5004".to_vec(),
        b"".to_vec(),
        join(&[b"[", RINGTONE, b"]"]),
        b"type=ringtone".to_vec(),
        join(&[b"alias=", RINGTONE_ALIAS]),
        b"filename=sonnerie.raw".to_vec(),
        b"".to_vec(),
    ];
    lines.join(&b"\n"[..])
}

/// `voicemail.conf`.
pub const VOICEMAIL_CONF: &[u8] = b"; dpma-rs raw-bytes test (tests/suites/raw-bytes)
[general]
format=wav

[default]
1001 => 1111,Jos\xe9 M\xfcller
";

/// A tenth of a second of silence (8 kHz, 16-bit mono).
fn wav() -> Vec<u8> {
    let data = vec![0u8; 1600];
    let mut out = b"RIFF".to_vec();
    out.extend_from_slice(&(36 + data.len() as u32).to_le_bytes());
    out.extend_from_slice(b"WAVEfmt ");
    out.extend_from_slice(&16u32.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&8000u32.to_le_bytes());
    out.extend_from_slice(&16000u32.to_le_bytes());
    out.extend_from_slice(&2u16.to_le_bytes());
    out.extend_from_slice(&16u16.to_le_bytes());
    out.extend_from_slice(b"data");
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend(data);
    out
}

/// The spool directory of mailbox 1001@default.
fn vm_box(inst: &Instance) -> PathBuf {
    inst.spool().join("voicemail").join("default").join("1001")
}

/// Writes voicemail message `num` of 1001@default.
fn message(inst: &Instance, num: u32, m: &VmMessage) -> Result<()> {
    let d = vm_box(inst).join(m.folder);
    std::fs::create_dir_all(&d)?;
    std::fs::write(d.join(format!("msg{num:04}.wav")), wav())?;
    let mut txt = b";\n; Message Information file\n;\n[message]\norigmailbox=1001\ncontext=default\nexten=1001\nrdnis=unknown\npriority=1\ncallerchan=Local/1001@default-0;2\n".to_vec();
    txt.extend_from_slice(b"callerid=");
    txt.extend_from_slice(m.callerid);
    txt.push(b'\n');
    txt.extend_from_slice(
        format!(
            "origdate=Sat Jan  1 12:00:00 AM UTC 2022\norigtime={}\ncategory=\nmsg_id={}\nflag=\nduration=1\n",
            m.origtime, m.msg_id
        )
        .as_bytes(),
    );
    std::fs::write(d.join(format!("msg{num:04}.txt")), txt)?;
    Ok(())
}

/// Installs the configuration into the instance: `res_digium_phone.conf`
/// and `voicemail.conf` (replacing the instance's), the files the phones
/// refer to in `file_directory`, and the voicemail messages of
/// 1001@default.
pub fn install(inst: &Instance) -> Result<()> {
    std::fs::write(inst.conf("res_digium_phone.conf"), conf())?;
    std::fs::write(inst.conf("voicemail.conf"), VOICEMAIL_CONF)?;
    let files = inst.var_lib().join("digium_phones");
    std::fs::create_dir_all(&files)?;
    for (name, data) in [(CONTACT_FILE, CONTACT_XML), (RULES_FILE, RULES_XML)] {
        std::fs::write(files.join(OsStr::from_bytes(name)), data)
            .with_context(|| files.display().to_string())?;
    }
    let vm = vm_box(inst);
    if vm.is_dir() {
        std::fs::remove_dir_all(&vm)?;
    }
    message(inst, 0, &VM_LATIN1)?;
    message(inst, 0, &VM_UTF8)?;
    Ok(())
}
