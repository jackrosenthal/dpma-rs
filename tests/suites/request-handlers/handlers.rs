//! The phone request handlers.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use bstr::{BString, ByteSlice};
use dpma_tests::harness::{ConfFile, Ctx};
use dpma_tests::sim::proto::method_request_json;
use dpma_tests::sim::{Exchange, Phone};
use dpma_tests::util::json_compact;
use serde_json::{json, Value};

use crate::common::*;

/// The test `file_directory`: `<instance>/var/lib/asterisk/test_files`.
pub fn files_dir(ctx: &Ctx) -> PathBuf {
    ctx.inst.var_lib().join("test_files")
}

/// The files the FileRequest and `config_file` checks read, by their
/// path relative to the file directory (`test-big.bin` is made by
/// [`make_files`]).
const FILES: [(&str, &[u8]); 6] = [
    ("test-small.txt", b"line one\nline two\n"),
    (
        "phonec-config.xml",
        b"<config>\n<!-- phonec's own configuration file -->\n</config>\n",
    ),
    ("sub/test-sub.txt", b"in a subdirectory\n"),
    ("..test-dots.txt", b"two dots\n"),
    ("sub/..test-dots.txt", b"two dots in sub\n"),
    ("../test-outside.txt", b"outside\n"),
];

/// Writes the test files into the file directory `dir`.
fn make_files(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir.join("sub"))?;
    let mut big: Vec<u8> = (0..=255u8).cycle().take(256 * 20).collect();
    big.extend_from_slice(b"\0end");
    std::fs::write(dir.join("test-big.bin"), big)?;
    for (name, data) in FILES {
        std::fs::write(dir.join(name), data)?;
    }
    Ok(())
}

/// Runs a part of the request handler checks: makes the test files,
/// saves `res_digium_phone.conf` (the parts change `[general]`), and
/// restores it (and reloads the module) at the end.
pub fn part(ctx: &mut Ctx, f: fn(&mut Ctx) -> Result<()>) -> Result<()> {
    make_files(&files_dir(ctx))?;
    let backup = ConfFile::new(&ctx.inst.conf("res_digium_phone.conf")).backup()?;
    let res = f(ctx);
    backup.restore()?;
    cli(ctx, "module reload res_dpma_rs.so")?;
    res
}

/// The contents of a test file.
fn read(path: &Path) -> Result<Vec<u8>> {
    std::fs::read(path).with_context(|| path.display().to_string())
}

// ---------------------------------------------------------------------------
// TokenRequest

fn expected_token_error(flags: u32, mac_ok: bool, pin: &str, cfgpass: &str) -> Option<i64> {
    let cp_ok = cfgpass == GLOBALPIN || cfgpass == "7777";
    if flags & GLOBAL != 0 && !cp_ok {
        return Some(-198);
    }
    if (flags & MAC != 0 && !mac_ok) || (flags & PIN != 0 && pin != "4321") {
        return Some(-195);
    }
    None
}

/// The token phonea gets from a phone with MAC `mac`.
fn phonea_token(mac: &str) -> BString {
    format!(
        "phonea/{mac}/{}/{}",
        token_hash(b""),
        token_hash(GLOBALPIN.as_bytes())
    )
    .into()
}

pub fn token(ctx: &mut Ctx) -> Result<()> {
    ctx.c.say("-- TokenRequest in every config_auth mode");
    let combos = [
        ("4321", GLOBALPIN),
        ("4321", "7777"),
        ("bad", "bad"),
        ("", ""),
        ("4321", "bad"),
        ("bad", GLOBALPIN),
    ];
    for (mode, flags) in MODES {
        set_auth(ctx, mode, "disabled")?;
        let good = phone(ctx, MAC_A)?;
        let bad = phone(ctx, MAC_BAD)?;
        for (p, mac_ok) in [(&good, true), (&bad, false)] {
            for (pin, cfgpass) in combos {
                let err = expected_token_error(flags, mac_ok, pin, cfgpass);
                let name = format!(
                    "token {mode} mac={} pin={pin:?} configpass={cfgpass:?}",
                    if mac_ok { "ok" } else { "bad" }
                );
                let ex = p
                    .get_token()
                    .user("phonea")
                    .pin(pin)
                    .config_password(cfgpass)
                    .send()?;
                let body = if err.is_none() {
                    Body::Is(b"empty body")
                } else {
                    Body::Default
                };
                let Some(r) = expect(ctx, &name, &ex, "TokenResponse", err, body) else {
                    continue;
                };
                let want = err.is_none().then(|| phonea_token(p.mac()));
                ctx.c.same(
                    format!("{name} (token)"),
                    r.field("Config-Token").cloned(),
                    want,
                );
            }
        }
    }

    ctx.c
        .say("-- TokenRequest: selecting the phone, side effects");
    set_auth(ctx, "mac_globalpin", "disabled")?;
    {
        let p = phone(ctx, MAC_A)?;
        let sid = sid(&p);
        let got = configured(ctx, &sid)?;
        ctx.c
            .same("new session is not configured", got.as_deref(), Some("No"));
        // By the primary line's name and extension, and by MAC alone.
        for user in [Some("phonea-line"), Some("5201"), Some("PHONEA-LINE"), None] {
            let mut b = p.get_token().config_password(GLOBALPIN);
            if let Some(u) = user {
                b = b.user(u);
            }
            let ex = b.send()?;
            let name = format!("token for user {user:?}");
            if let Some(r) = expect(ctx, &name, &ex, "TokenResponse", None, Body::Default) {
                ctx.c.same(
                    format!("{name} (token)"),
                    r.field("Config-Token").cloned(),
                    Some(phonea_token(MAC_A)),
                );
            }
        }
        let got = configured(ctx, &sid)?;
        ctx.c.same(
            "token marks the session configured",
            got.as_deref(),
            Some("Yes"),
        );
        let info = cli(ctx, "dpmadev token info phonea")?;
        let db = capture(r"AstDB: (.*)", &info).map(|s| s.trim().to_string());
        ctx.c.same(
            "token records the last info (AstDB)",
            db,
            Some(format!(
                "last_mac={MAC_A};last_uri=pjsip:127.0.0.1:{};transport=udp;last_session_id={sid}",
                p.local_addr().port()
            )),
        );
        let ex = p
            .get_token()
            .user("nosuchphone")
            .config_password(GLOBALPIN)
            .send()?;
        expect(
            ctx,
            "token for an unknown user",
            &ex,
            "TokenResponse",
            Some(-195),
            Body::Default,
        );
        // A MAC no phone has and no user name.
        let q = phone(ctx, "000fd30012ee")?;
        let ex = q.get_token().config_password(GLOBALPIN).send()?;
        expect(
            ctx,
            "token by an unknown MAC",
            &ex,
            "TokenResponse",
            Some(-195),
            Body::Default,
        );
    }
    // Neither a MAC nor a user name (the phone handshakes without a MAC).
    let mut o = ctx.sim_options().mac("");
    o.contact = Some("sip:nomac@127.0.0.1:5999".into());
    let q = dpma_tests::harness::fixtures::phone(o)?;
    let mark = log_mark(ctx);
    let ex = q.get_token().config_password(GLOBALPIN).send()?;
    expect(
        ctx,
        "token without MAC and user name",
        &ex,
        "TokenResponse",
        Some(-195),
        Body::Default,
    );
    logged(
        ctx,
        "token without MAC and user name (log)",
        mark,
        "The MAC and USERNAME headers are required in a token request. \n",
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// ConfigRequest and VerifyRequest

pub fn config(ctx: &mut Ctx) -> Result<()> {
    let files = files_dir(ctx);
    let files_s = files.to_string_lossy().into_owned();
    set_general(
        ctx,
        &[
            ("config_auth", Some("mac_globalpin")),
            ("userlist_auth", Some("disabled")),
            ("globalpin", Some(GLOBALPIN)),
            ("file_directory", Some(&files_s)),
        ],
    )?;
    {
        let p = phone(ctx, MAC_A)?;
        let sid = sid(&p);
        let ex = p.request("ConfigRequest").send()?;
        expect(
            ctx,
            "config without a token",
            &ex,
            "ConfigResponse",
            Some(-192),
            Body::Default,
        );
        let ex = p.config().config_token("phonea/000fd3999999/1/2").send()?;
        expect(
            ctx,
            "config with a bad token",
            &ex,
            "ConfigResponse",
            Some(-192),
            Body::Default,
        );
        let got = configured(ctx, &sid)?;
        ctx.c.same(
            "failed config leaves the session unconfigured",
            got.as_deref(),
            Some("No"),
        );
        let mark = log_mark(ctx);
        let ex = p.request("VerifyRequest").send()?;
        expect(
            ctx,
            "verify without a token",
            &ex,
            "VerifyResponse",
            Some(-192),
            Body::Default,
        );
        logged(
            ctx,
            "verify without a token (log)",
            mark,
            "Verify request with null token\n",
        );
        let got = configured(ctx, &sid)?;
        ctx.c.same(
            "verify without a token leaves the session unconfigured",
            got.as_deref(),
            Some("No"),
        );
        let ex = p.verify().config_token("nobody/x").send()?;
        expect(
            ctx,
            "verify with a bad token",
            &ex,
            "VerifyResponse",
            Some(-192),
            Body::Default,
        );
        let got = configured(ctx, &sid)?;
        ctx.c.same(
            "verify with a bad token marks the session configured",
            got.as_deref(),
            Some("Yes"),
        );
        cli(ctx, &format!("dpmadev session mark {sid} unconfigured"))?;

        let ex = p
            .get_token()
            .user("phonea")
            .config_password(GLOBALPIN)
            .send()?;
        expect(ctx, "token", &ex, "TokenResponse", None, Body::Default);
        cli(ctx, &format!("dpmadev session mark {sid} unconfigured"))?;
        let want = cli(ctx, "dpmadev config phonea D65")?;
        let ex = p.config().send()?;
        if let Some(r) = expect(
            ctx,
            "config with the token",
            &ex,
            "ConfigResponse",
            None,
            Body::Matches(r"\A<config>"),
        ) {
            ctx.c.same_bytes(
                "config document = get_config(phonea, D65)",
                r.payload.trim_end_with(|c| c == '\n'),
                want.trim_end_with(|c| c == '\n'),
            );
        }
        let got = configured(ctx, &sid)?;
        ctx.c.same(
            "config marks the session configured",
            got.as_deref(),
            Some("Yes"),
        );
        // The prefix <phone><sep><last MAC> is all that is compared.
        let ex = p
            .config()
            .config_token(format!("phonea-{MAC_A}-anything"))
            .send()?;
        expect(
            ctx,
            "config with a '-' token",
            &ex,
            "ConfigResponse",
            None,
            Body::Matches(r"\A<config>"),
        );
        cli(ctx, &format!("dpmadev session mark {sid} unconfigured"))?;
        let ex = p.verify().send()?;
        expect(
            ctx,
            "verify with the token",
            &ex,
            "VerifyResponse",
            None,
            Body::Is(b"empty body"),
        );
        let got = configured(ctx, &sid)?;
        ctx.c.same(
            "verify marks the session configured",
            got.as_deref(),
            Some("Yes"),
        );
    }

    // A phone with config_file: the file from file_directory instead.
    let p = phone(ctx, "000fd3001203")?;
    let ex = p
        .get_token()
        .user("phonec")
        .config_password("8888")
        .send()?;
    expect(
        ctx,
        "token phonec",
        &ex,
        "TokenResponse",
        None,
        Body::Default,
    );
    let want = read(&files.join("phonec-config.xml"))?;
    let ex = p.config().send()?;
    expect(
        ctx,
        "config_file is read from file_directory",
        &ex,
        "ConfigResponse",
        None,
        Body::Is(&want),
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// UserlistRequest

/// The names of a user list document (`None` when it is not one).
fn users_of(payload: &[u8]) -> Option<Vec<String>> {
    let v: Value = serde_json::from_slice(payload).ok()?;
    v.get("users")?
        .as_array()?
        .iter()
        .map(|u| {
            let name = u.as_object()?.get("name")?;
            Some(
                name.as_str()
                    .map_or_else(|| name.to_string(), str::to_string),
            )
        })
        .collect()
}

pub fn userlist(ctx: &mut Ctx) -> Result<()> {
    let mut all_names: Option<Vec<String>> = None;
    let users_doc = regex::bytes::Regex::new(r#"\{"users":.*\}"#).expect("pattern");
    for mode in ["disabled", "globalpin"] {
        set_auth(ctx, "mac_globalpin", mode)?;
        let p = phone(ctx, MAC_A)?;
        let sid = sid(&p);
        cli(ctx, &format!("dpmadev session mark {sid} configured"))?;
        let want = cli(ctx, &format!("dpmadev userlist {GLOBALPIN}"))?;
        let ex = p.userlist().config_password(GLOBALPIN).send()?;
        if let Some(r) = expect(
            ctx,
            &format!("userlist ({mode}) with the global pin"),
            &ex,
            "UserlistResponse",
            None,
            Body::Default,
        ) {
            let doc = users_doc
                .find(&want)
                .map_or(want.to_vec(), |m| m.as_bytes().to_vec());
            ctx.c.same_bytes(
                format!("userlist ({mode}) = build_userlist_json"),
                &r.payload,
                &doc,
            );
            all_names = users_of(&r.payload);
        }
        let got = configured(ctx, &sid)?;
        ctx.c.same(
            "userlist marks the session unconfigured",
            got.as_deref(),
            Some("No"),
        );
        for cfgpass in ["7777", "8888", "", "wrong"] {
            let name = format!("userlist ({mode}) with config pass {cfgpass:?}");
            clear_incidents(ctx)?;
            let mark = log_mark(ctx);
            let ex = p.userlist().config_password(cfgpass).send()?;
            if mode == "disabled" {
                let r = expect(ctx, &name, &ex, "UserlistResponse", None, Body::Default);
                let got = r.and_then(|r| users_of(&r.payload));
                ctx.c
                    .same(format!("{name} lists everyone"), got, all_names.clone());
                continue;
            }
            let want_names: Option<&[&str]> = match cfgpass {
                "7777" => Some(&["Test Phone A", "phoneb"]),
                "8888" => Some(&["phonec"]),
                _ => None,
            };
            if let Some(want_names) = want_names {
                let r = expect(ctx, &name, &ex, "UserlistResponse", None, Body::Default);
                let got = r.and_then(|r| users_of(&r.payload)).map(|mut g| {
                    g.sort();
                    g
                });
                let want: Vec<String> = want_names.iter().map(|s| s.to_string()).collect();
                ctx.c
                    .same(format!("{name} lists the group"), got, Some(want));
                continue;
            }
            expect(
                ctx,
                &name,
                &ex,
                "UserlistResponse",
                Some(-198),
                Body::Default,
            );
            logged(
                ctx,
                &format!("{name} (log)"),
                mark,
                "Userlist request with invalid config password, or no users configured.\n",
            );
            let inc = local_incident(ctx)?;
            let ok = inc.as_ref().is_some_and(|i| {
                field(i, "Reason").as_deref() == Some("invalid config pass")
                    && field(i, "MAC").as_deref() == Some(MAC_A)
                    && field(i, "IncidentCount").as_deref() == Some("1")
            });
            ctx.c.check(
                format!("{name} records an incident"),
                ok,
                format!("{inc:?}"),
            );
        }
    }
    clear_incidents(ctx)
}

// ---------------------------------------------------------------------------
// FileRequest

pub fn file(ctx: &mut Ctx) -> Result<()> {
    let files = files_dir(ctx);
    let files_s = files.to_string_lossy().into_owned();
    set_general(
        ctx,
        &[
            ("config_auth", Some("mac_globalpin")),
            ("userlist_auth", Some("disabled")),
            ("globalpin", Some(GLOBALPIN)),
            ("file_directory", Some(&files_s)),
        ],
    )?;
    let p = phone(ctx, MAC_A)?;
    let want = cli(ctx, "dpmadev contacts")?;
    for name in ["default", "DEFAULT"] {
        let ex = p.file(name).send()?;
        if let Some(r) = expect(
            ctx,
            &format!("file://{name}"),
            &ex,
            "FileResponse",
            None,
            Body::Matches(r#"\A<contacts group_name="Internal Extensions" editable="0" >\n"#),
        ) {
            ctx.c.same_bytes(
                format!("file://{name} = default contacts"),
                r.payload.trim_end_with(|c| c == '\n'),
                want.trim_end_with(|c| c == '\n'),
            );
        }
    }
    let ex = p.file("Null").send()?;
    expect(
        ctx,
        "file://null",
        &ex,
        "FileResponse",
        None,
        Body::Is(b"<contacts group_name=\"null\" editable=\"0\" />\n"),
    );
    for fname in ["test-small.txt", "test-big.bin"] {
        let data = read(&files.join(fname))?;
        let ex = p.file(fname).send()?;
        let r = expect(
            ctx,
            &format!("file://{fname} ({} bytes)", data.len()),
            &ex,
            "FileResponse",
            None,
            Body::Is(&data),
        );
        if let (Some(r), "test-big.bin") = (r, fname) {
            ctx.c.check(
                format!("file://{fname} came in several chunks"),
                r.parts.len() > 1,
                r.parts.len(),
            );
        }
    }
    let small = read(&files.join("test-small.txt"))?;
    let ex = p
        .request("FileRequest")
        .body("some text\r\nfile://test-small.txt\r\nmore text")
        .send()?;
    expect(
        ctx,
        "file:// inside the body, up to the line end",
        &ex,
        "FileResponse",
        None,
        Body::Is(&small),
    );
    let mark = log_mark(ctx);
    let ex = p.file("missing.txt").send()?;
    expect(
        ctx,
        "file://missing.txt",
        &ex,
        "FileResponse",
        Some(-98),
        Body::Default,
    );
    logged(
        ctx,
        "file://missing.txt (log)",
        mark,
        &format!("Failed to open file {files_s}/missing.txt\n"),
    );
    let ex = p.request("FileRequest").body("default").send()?;
    expect(
        ctx,
        "body without file://",
        &ex,
        "FileResponse",
        Some(-98),
        Body::Default,
    );
    let ex = p.request("FileRequest").body("").send()?;
    expect(
        ctx,
        "empty body",
        &ex,
        "FileResponse",
        Some(-98),
        Body::Default,
    );
    // An empty name opens the directory itself, which reads as nothing.
    let ex = p.request("FileRequest").body("file://").send()?;
    expect(
        ctx,
        "file:// with no name",
        &ex,
        "FileResponse",
        None,
        Body::Is(b"empty body"),
    );
    // Subdirectories of file_directory are served; names with a ".."
    // component are refused like a missing file, although the files exist.
    // Absolute names are looked up inside file_directory, as the official
    // DPMA does ("<dir>//test-small.txt").
    for fname in [
        "sub/test-sub.txt",
        "./sub/./test-sub.txt",
        "..test-dots.txt",
        "sub/..test-dots.txt",
    ] {
        let data = read(&files.join(fname))?;
        let ex = p.file(fname).send()?;
        expect(
            ctx,
            &format!("file://{fname}"),
            &ex,
            "FileResponse",
            None,
            Body::Is(&data),
        );
    }
    for fname in ["/test-small.txt", "//test-small.txt"] {
        let ex = p.file(fname).send()?;
        expect(
            ctx,
            &format!("file://{fname} (inside file_directory)"),
            &ex,
            "FileResponse",
            None,
            Body::Is(&small),
        );
    }
    let outside = files
        .parent()
        .unwrap_or(&files)
        .join("test-outside.txt")
        .to_string_lossy()
        .into_owned();
    for fname in [outside.as_str(), "//etc/hostname"] {
        let mark = log_mark(ctx);
        let ex = p.file(fname).send()?;
        expect(
            ctx,
            &format!("file://{fname} (not inside file_directory)"),
            &ex,
            "FileResponse",
            Some(-98),
            Body::Default,
        );
        logged(
            ctx,
            &format!("file://{fname} (log)"),
            mark,
            &format!("Failed to open file {files_s}/{fname}\n"),
        );
    }
    for fname in [
        "../test-outside.txt",
        "sub/../../test-outside.txt",
        "sub/../test-small.txt",
        "..",
        "sub/..",
        "/../test-outside.txt",
    ] {
        let mark = log_mark(ctx);
        let ex = p.file(fname).send()?;
        expect(
            ctx,
            &format!("file://{fname} refused"),
            &ex,
            "FileResponse",
            Some(-98),
            Body::Default,
        );
        logged(
            ctx,
            &format!("file://{fname} refused (log)"),
            mark,
            &format!("File request for '{fname}' outside the file directory refused\n"),
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// AsteriskRequest and HTTPRequest (JSON)

/// An AsteriskRequest (or HTTPRequest) with the credentials `auth`.
fn call(p: &Phone, auth: &str, doc: &str, rtype: &str) -> Result<Exchange> {
    let b = if rtype == "HTTPRequest" {
        p.http(doc)
    } else {
        p.asterisk(doc)
    };
    b.auth(auth).send()
}

/// A method call document with JSON parameters.
fn method_request(method: &str, params: Value) -> String {
    method_request_json(method, Some(&params))
}

pub fn asterisk(ctx: &mut Ctx) -> Result<()> {
    set_auth(ctx, "mac_globalpin", "disabled")?;
    cli(ctx, "dpmadev method register json test.Who.Json")?;
    let res = asterisk_checks(ctx);
    cli(ctx, "dpmadev method unregister json test.Who.Json")?;
    res
}

fn asterisk_checks(ctx: &mut Ctx) -> Result<()> {
    let p = phone(ctx, MAC_A)?;
    // Every JSON value type through jansson and back; the request escapes
    // the non-ASCII and control characters (\u00e9, \u0001), the reply
    // escapes only the control character.
    let echo = method_request(
        "test.dpma.api.echo",
        json!({"a": "b", "n": [1, 2.5, null, true], "o": {"x": "é\u{1}/"}}),
    );
    let want = http(
        r#"{"response":{"method":"test.dpma.api.echo","result":{"a":"b","n":[1,2.5,null,true],"o":{"x":"é\u0001/"}}}}"#
            .as_bytes(),
    );
    let ex = call(&p, "simphone:1234", &echo, "AsteriskRequest")?;
    expect(
        ctx,
        "echo, phone pin",
        &ex,
        "AsteriskResponse",
        None,
        Body::Is(&want),
    );
    let ex = call(&p, "phoneb:", &echo, "HTTPRequest")?;
    expect(
        ctx,
        "echo as HTTPRequest, a phone without a pin and an empty secret",
        &ex,
        "HTTPResponse",
        None,
        Body::Is(&want),
    );
    // The credentials line after the request.
    let ex = p
        .request("AsteriskRequest")
        .body(format!(
            "{echo}\r\nX-Digium-AppServer-Digest-Auth=simphone:1234"
        ))
        .send()?;
    expect(
        ctx,
        "credentials after the request",
        &ex,
        "AsteriskResponse",
        None,
        Body::Is(&want),
    );

    let who = |ctx: &mut Ctx, auth: &str, phone_name: &str, name: &str, method: &str| {
        let doc = method_request(method, json!({"k": "v"}));
        let body = json_compact(&json!({"response": {"method": method, "result": {
            "phone": phone_name, "registry": "json", "parameters": {"k": "v"}}}}));
        let ex = call(&p, auth, &doc, "AsteriskRequest")?;
        expect(
            ctx,
            name,
            &ex,
            "AsteriskResponse",
            None,
            Body::Is(&http(body.as_bytes())),
        );
        anyhow::Ok(())
    };
    let m = "test.Who.Json";
    who(ctx, "phonea:4321", "phonea", "phone name and pin", m)?;
    who(
        ctx,
        "  phonea :\t4321  ",
        "phonea",
        "blanks around the credentials",
        m,
    )?;
    who(
        ctx,
        "phonea-line:lsecret",
        "phonea",
        "line name and secret authenticate the line's phone",
        m,
    )?;
    who(
        ctx,
        "phoneb",
        "phoneb",
        "no colon: a phone without a pin",
        m,
    )?;
    who(
        ctx,
        "phoneb-line",
        "phoneb",
        "no colon: a line without a secret",
        m,
    )?;
    who(
        ctx,
        "phonea:4321",
        "phonea",
        "method name as requested",
        "TEST.WHO.JSON",
    )?;
    who(
        ctx,
        "PHONEA:4321",
        "phonea",
        "phone names match case insensitively",
        m,
    )?;

    for auth in [
        "phonea:1234",
        "phonea",
        "phonea-line:wrong",
        "nosuch:1",
        ":4321",
        "phonea:4321x",
    ] {
        let mark = log_mark(ctx);
        let ex = call(&p, auth, &echo, "AsteriskRequest")?;
        let detail = format!("authentication failed for {}", auth.trim());
        expect(
            ctx,
            &format!("bad credentials {auth:?}"),
            &ex,
            "AsteriskResponse",
            None,
            Body::Is(&http(json_error("NA", 99999, &detail).as_bytes())),
        );
        logged(
            ctx,
            &format!("bad credentials {auth:?} (log)"),
            mark,
            &format!(
                "Authentication failed for user credentials: {}\n",
                auth.trim()
            ),
        );
    }

    let mark = log_mark(ctx);
    let ex = p.request("AsteriskRequest").body(&echo).send()?;
    expect(
        ctx,
        "no credentials",
        &ex,
        "AsteriskResponse",
        None,
        Body::Is(&http(
            json_error("NA", 10002, "missing authentication credentials").as_bytes(),
        )),
    );
    logged(
        ctx,
        "no credentials (log)",
        mark,
        "No auth credentials found in phone msg\n",
    );
    let mark = log_mark(ctx);
    let ex = call(&p, "simphone:1234", "hello", "AsteriskRequest")?;
    expect(
        ctx,
        "no request",
        &ex,
        "AsteriskResponse",
        None,
        Body::Is(&http(json_error("NA", 10002, "empty json body").as_bytes())),
    );
    logged(
        ctx,
        "no request (log)",
        mark,
        "No xml request body found in phone msg:\n",
    );
    let cases: [(&str, &str, u32, &str); 7] = [
        (
            r#"{"request": {"method": "test.dpma.api.echo", "parameters": {}"#,
            "NA",
            10002,
            "json body",
        ),
        (r#"{"request": 5}"#, "NA", 10002, "no request in body"),
        (
            r#"{"request": {"parameters": {}}}"#,
            "NA",
            10002,
            "no method in body",
        ),
        (
            r#"{"request": {"method": 7, "parameters": {}}}"#,
            "NA",
            10002,
            "no method in body",
        ),
        (
            r#"{"request": {"method": "test.dpma.api.echo"}}"#,
            "test.dpma.api.echo",
            10001,
            "request contains no parameters",
        ),
        (
            r#"{"request": {"method": "no.such.method", "parameters": {}}}"#,
            "no.such.method",
            10005,
            "no.such.method",
        ),
        (
            r#"{"request": {"method": "", "parameters": {}}}"#,
            "NA",
            10005,
            "",
        ),
    ];
    for (doc, method, code, detail) in cases {
        let ex = call(&p, "simphone:1234", doc, "AsteriskRequest")?;
        expect(
            ctx,
            &format!("JSON {doc}"),
            &ex,
            "AsteriskResponse",
            None,
            Body::Is(&http(json_error(method, code, detail).as_bytes())),
        );
    }
    // A method that answers nothing (getTodaysStatus without a queue
    // application).
    let m = "switchvox.users.callQueues.getTodaysStatus";
    let doc = method_request(
        m,
        json!({"account_id": "1001", "call_queue_account_id": "nosuchqueue"}),
    );
    let ex = call(&p, "simphone:1234", &doc, "AsteriskRequest")?;
    expect(
        ctx,
        "empty method response",
        &ex,
        "AsteriskResponse",
        None,
        Body::Is(&http(
            json_error(m, 10002, "empty response body").as_bytes(),
        )),
    );
    // Multi-chunk request and reply.
    let big = json!({"data": "x".repeat(3000), "n": (0..200).collect::<Vec<u32>>()});
    let ex = call(
        &p,
        "simphone:1234",
        &method_request("test.dpma.api.echo", big.clone()),
        "AsteriskRequest",
    )?;
    let want = http(
        json_compact(&json!({"response": {"method": "test.dpma.api.echo", "result": big}}))
            .as_bytes(),
    );
    if let Some(r) = expect(
        ctx,
        "multi-chunk echo",
        &ex,
        "AsteriskResponse",
        None,
        Body::Is(&want),
    ) {
        ctx.c.check(
            "multi-chunk echo: request and reply in several chunks",
            ex.chunks > 1 && r.parts.len() > 1,
            format!("{} / {}", ex.chunks, r.parts.len()),
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// XML requests

pub fn xml(ctx: &mut Ctx) -> Result<()> {
    set_auth(ctx, "mac_globalpin", "disabled")?;
    cli(ctx, "dpmadev method register xml test.Who.Xml")?;
    let res = xml_checks(ctx);
    cli(ctx, "dpmadev method unregister xml test.Who.Xml")?;
    res
}

fn xml_checks(ctx: &mut Ctx) -> Result<()> {
    let p = phone(ctx, MAC_A)?;
    let params = r#"<parameters><a x="1">t &amp; u</a><b/></parameters>"#;
    let doc = format!(r#"<request method="Test.who.xml">{params}</request>"#);
    cli(ctx, "core set debug 3 res_dpma_rs")?;
    let mark = log_mark(ctx);
    let want = http(
        format!(
            r#"<response method="Test.who.xml"><result phone="phonea" registry="xml">{params}</result></response>"#
        )
        .as_bytes(),
    );
    let ex = call(&p, "phonea:4321", &doc, "AsteriskRequest")?;
    expect(
        ctx,
        "XML method gets phone, method, and <parameters>",
        &ex,
        "AsteriskResponse",
        None,
        Body::Is(&want),
    );
    logged(
        ctx,
        "XML debug log",
        mark,
        "Asterisk request method 'Test.who.xml' is using XML body\n",
    );
    cli(ctx, "core set debug 0 res_dpma_rs")?;
    let cases = [
        (r#"<request method="test.who.xml"/>"#, "test.who.xml", 10001),
        (r#"<request method=""><parameters/></request>"#, "NA", 10003),
        (
            r#"<request method="test.who.xml"><params/></request>"#,
            "test.who.xml",
            10011,
        ),
        (
            r#"<request method="no.such.method"><parameters/></request>"#,
            "no.such.method",
            10005,
        ),
        (
            r#"<request method="test.who.xml"><parameters>"#,
            "NA",
            10002,
        ),
    ];
    for (d, method, code) in cases {
        let ex = call(&p, "phonea:4321", d, "AsteriskRequest")?;
        expect(
            ctx,
            &format!("XML {d}"),
            &ex,
            "AsteriskResponse",
            None,
            Body::Is(&http(xml_error(method, code).as_bytes())),
        );
    }
    // Text before the request element is ignored.
    let ex = call(&p, "phonea:4321", &format!("junk {doc}"), "AsteriskRequest")?;
    expect(
        ctx,
        "XML after other text",
        &ex,
        "AsteriskResponse",
        None,
        Body::Is(&want),
    );
    // A built-in XML method: startRecording without parameters.
    let m = "switchvox.users.currentCalls.startRecording";
    let d = format!(r#"<request method="{m}"><parameters/></request>"#);
    let ex = call(&p, "phonea:4321", &d, "AsteriskRequest")?;
    expect(
        ctx,
        "built-in XML method",
        &ex,
        "AsteriskResponse",
        None,
        Body::Is(&http(xml_error(m, 10011).as_bytes())),
    );
    // JSON-only methods are not XML methods.
    let d = r#"<request method="test.dpma.api.echo"><parameters/></request>"#;
    let ex = call(&p, "phonea:4321", d, "AsteriskRequest")?;
    expect(
        ctx,
        "JSON-only method requested as XML",
        &ex,
        "AsteriskResponse",
        None,
        Body::Is(&http(xml_error("test.dpma.api.echo", 10005).as_bytes())),
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Methods registered by AMI: the DPMAMessage event

pub fn ami(ctx: &mut Ctx) -> Result<()> {
    set_auth(ctx, "mac_globalpin", "disabled")?;
    let res = ami_checks(ctx);
    cli(ctx, "dpmadev method unregister ami test.ami.method")?;
    res
}

/// What the request handler gives the DPMAMessage event of an
/// AMI-registered method: the method as requested and the parameters.
fn ami_checks(ctx: &mut Ctx) -> Result<()> {
    let ok = ctx
        .ami()?
        .action("DPMAMessageRegister", [("Method", "test.ami.method")])
        .success();
    ctx.c.require("DPMAMessageRegister", ok, "")?;
    let p = phone(ctx, MAC_A)?;
    ctx.ami()?.drain_events();
    let json_doc = method_request(
        "test.AMI.method",
        json!({"a": [1, 2.5, "x"], "b": {"c": null}}),
    );
    for (fmt, doc, params) in [
        (
            "JSON",
            json_doc.as_str(),
            r#"{"a":[1,2.5,"x"],"b":{"c":null}}"#,
        ),
        (
            "XML",
            r#"<request method="test.AMI.method"><parameters><a>one</a> <b>two</b></parameters></request>"#,
            "one two",
        ),
    ] {
        let mut ex = p.asterisk(doc).auth("phonea:4321").no_wait().send()?;
        let ev = ctx
            .ami()?
            .wait_event(Some("DPMAMessage"), &[], Duration::from_secs(5));
        let f = |k: &str| ev.as_ref().and_then(|ev| field(ev, k));
        ctx.c.same(
            format!("{fmt}: Method as requested"),
            f("Method").as_deref(),
            Some("test.AMI.method"),
        );
        ctx.c.same(
            format!("{fmt}: Parameters"),
            f("Parameters").as_deref(),
            Some(params),
        );
        // Answer it, so that it does not stay queued.
        let rid = format!("{}-{MAC_A}", ex.id);
        ctx.ami()?.action(
            "DPMAMessageResponse",
            [
                ("RequestID", rid.as_str()),
                ("Format", fmt),
                ("Response", "ok"),
            ],
        );
        p.wait_reply(&mut ex, Some(Duration::from_secs(5)));
    }
    // Parameters that are not an object or array: queued without an event
    // (the handler raises the event before it queues the request).
    let mut ex = p
        .asterisk(method_request("test.ami.method", json!("scalar")))
        .auth("phonea:4321")
        .no_wait()
        .send()?;
    let rid = format!("{}-{MAC_A}", ex.id);
    let queued =
        dpma_tests::util::wait_until(Duration::from_secs(5), Duration::from_millis(20), || {
            cli_text(ctx, "dpmadev ami queue").is_ok_and(|q| q.contains(&rid))
        });
    ctx.c
        .check("JSON scalar parameters: queued", queued, "not in the queue");
    let ev = ctx
        .ami()?
        .wait_event(Some("DPMAMessage"), &[], Duration::from_millis(200));
    ctx.c.check(
        "JSON scalar parameters: no DPMAMessage",
        ev.is_none(),
        format!("{ev:?}"),
    );
    p.wait_reply(&mut ex, Some(Duration::from_millis(200)));
    ctx.c
        .check("JSON scalar parameters: no reply", ex.reply.is_none(), "");
    // A built-in method shadows an AMI registration of the same name.
    cli(ctx, "dpmadev method register ami test.dpma.api.echo")?;
    let ex = call(
        &p,
        "simphone:1234",
        &method_request("test.dpma.api.echo", json!({"x": 1})),
        "AsteriskRequest",
    )?;
    expect(
        ctx,
        "built-in method wins over AMI",
        &ex,
        "AsteriskResponse",
        None,
        Body::Is(&http(
            br#"{"response":{"method":"test.dpma.api.echo","result":{"x":1}}}"#,
        )),
    );
    cli(ctx, "dpmadev method unregister ami test.dpma.api.echo")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Handshake without a user agent

pub fn handshake(ctx: &mut Ctx) -> Result<()> {
    clear_incidents(ctx)?;
    let res = handshake_checks(ctx);
    clear_incidents(ctx)?;
    res
}

/// Sends a handshake that fails and waits until the module logged `last`
/// (the handshake handler's last line); then a reply can no longer come.
fn failed_handshake(
    ctx: &mut Ctx,
    p: &Phone,
    bundle: Option<&str>,
    last: &str,
) -> Result<Exchange> {
    let mark = log_mark(ctx);
    let mut b = p.handshake().no_wait();
    if let Some(bundle) = bundle {
        b = b.bundle(bundle);
    }
    let mut ex = b.send()?;
    logged(ctx, &format!("log: {last}"), mark, last);
    p.wait_reply(&mut ex, Some(Duration::from_millis(200)));
    Ok(ex)
}

fn handshake_checks(ctx: &mut Ctx) -> Result<()> {
    let mut o = ctx.sim_options().mac(MAC_A);
    o.user_agent = BString::default();
    let p = Phone::start(o)?;
    let mark = log_mark(ctx);
    let last = "Failed to create auth problem record";
    let ex = failed_handshake(ctx, &p, None, last)?;
    ctx.c.check("no reply", ex.reply.is_none(), ex.describe(0));
    for text in [
        "User Agent allocation failed",
        "Session could not be created due to invalid credentials",
    ] {
        logged(ctx, &format!("log: {text}"), mark, text);
    }
    let inc = local_incident(ctx)?;
    ctx.c.check(
        "no incident without a user agent",
        inc.is_none(),
        format!("{inc:?}"),
    );
    // With an incident for the address already there, it counts.
    {
        let q = Phone::start(ctx.sim_options().mac(MAC_A))?;
        let last = format!(
            "Auth failed for ip '127.0.0.1' mac '{MAC_A}' reason 'invalid credentials' count=1"
        );
        failed_handshake(ctx, &q, Some("rogue"), &last)?;
    }
    let inc = local_incident(ctx)?;
    ctx.c.same(
        "rogue certificate: incident",
        inc.as_ref()
            .map(|i| (field(i, "Reason"), field(i, "IncidentCount"))),
        Some((
            Some("invalid credentials".to_string()),
            Some("1".to_string()),
        )),
    );
    let last = format!(
        "Auth failed for ip '127.0.0.1' mac '{MAC_A}' reason 'invalid credentials' count=2"
    );
    failed_handshake(ctx, &p, None, &last)?;
    let inc = local_incident(ctx)?;
    ctx.c.same(
        "no user agent: the incident counts",
        inc.as_ref().and_then(|i| field(i, "IncidentCount")),
        Some("2".to_string()),
    );
    Ok(())
}
