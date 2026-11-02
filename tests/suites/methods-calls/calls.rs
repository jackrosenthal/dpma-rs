//! The parts: the scenarios of `run.py`.

use std::os::unix::fs::PermissionsExt;

use anyhow::Result;
use dpma_tests::harness::fixtures::sleep;
use regex::Regex;
use serde_json::{json, Map, Value};

use crate::{err, files_dir, ok, xml_err, xml_ok, PhoneLog, Via, T};

const Q: &str = "switchvox.users.callQueues.";

fn not_found(what: &str) -> String {
    format!("Parameters not found: {what} ")
}

fn success() -> Value {
    json!({"success": {}})
}

/// The keys of a JSON object, in order.
fn keys(v: &Value) -> Vec<&str> {
    v.as_object()
        .map(|o| o.keys().map(String::as_str).collect())
        .unwrap_or_default()
}

pub fn echo(t: &mut T) -> Result<()> {
    let m = "test.dpma.api.echo";
    let p = json!({"a": "b", "n": [1, 2.5, null, true], "o": {"x": "é\u{1}/"}});
    let (rc, body) = t.call("p10phone", m, &p)?;
    let want = r#"{"response":{"method":"test.dpma.api.echo","result":{"a":"b","n":[1,2.5,null,true],"o":{"x":"é\u0001/"}}}}"#;
    let good = t.rc_ok(rc, 0) && body == want;
    t.c().check("echo", good, body);
    Ok(())
}

/// getTodaysStatus with one call and one waiting caller: the details.
fn todays_status_ok(t: &T, rc: Option<i64>, body: &str) -> bool {
    let Ok(doc) = serde_json::from_str::<Value>(body) else {
        return false;
    };
    let cq = &doc["response"]["result"]["callQueue"];
    let member = &cq["detailed_view"]["queue_members"]["queue_member"][0];
    let caller = &cq["detailed_view"]["waiting_callers"]["waiting_caller"][0];
    let duration = match &member["call_duration"] {
        Value::String(s) => s.trim().parse::<i64>().ok(),
        Value::Number(n) => n.as_i64(),
        _ => None,
    };
    t.rc_ok(rc, 0)
        && keys(cq)
            == [
                "account_id",
                "name",
                "overview",
                "my_status",
                "detailed_view",
            ]
        && cq["account_id"] == "P10SALES"
        && cq["overview"]
            == json!({"total_members": "1", "logged_in_count": "1", "members_on_call": "1", "callers_waiting": "1",
                      "total_calls": "0", "completed_calls_today": "0", "abandoned_calls": "0",
                      "redirected_calls": "0", "longest_queue_length": "0", "avg_entry_position": "0"})
        && cq["my_status"] == json!({"login_status": ""})
        && keys(member) == ["loggedin_status", "call_duration", "fullname"]
        && member["fullname"] == "Alice P10"
        && duration.is_some_and(|d| d >= 1)
        && keys(caller)
            == [
                "talking_to_number",
                "talking_to_name",
                "position",
                "waiting_duration",
            ]
        && caller["talking_to_number"] == "5552000"
        && caller["position"] == "1"
}

pub fn queues(t: &mut T) -> Result<()> {
    let m = format!("{Q}getList");
    let got = t.call("p10phone", &m, &json!({}))?;
    t.expect(
        "getList: account_id required",
        got,
        -1,
        &err(&m, 10011, &not_found("account_id")),
    );
    let mark = t.log().mark();
    let got = t.call("p10phone", &m, &json!({"account_id": "1001"}))?;
    t.expect(
        "getList: nobody logged in",
        got,
        0,
        &ok(
            &m,
            json!({"callQueues": {"callQueue": [
                {"name": "p10sales", "account_id": "p10sales", "total_members": "0", "members_logged_in": "0", "callers_waiting": "0", "loggedin_status": "logged_out"},
                {"name": "p10support", "account_id": "p10support", "total_members": 0, "loggedin_status": "logged_out"},
                {"name": "p10static", "account_id": "p10static", "loggedin_status": "manager"},
                {"name": "p10ghost", "account_id": "p10ghost", "loggedin_status": "logged_out"}]}}),
        ),
    );
    let logged = t.logged(mark, "Failed to find application 'p10-nosuchapp'");
    t.c()
        .check("getList: missing application logged", logged, "");
    let got = t.call("p10phone2", &m, &json!({"account_id": "1002"}))?;
    t.expect(
        "getList: static member",
        got,
        0,
        &ok(
            &m,
            json!({"callQueues": {"callQueue": [
                {"name": "p10static", "account_id": "p10static", "loggedin_status": "permanent", "total_members": "1", "members_logged_in": "1", "callers_waiting": "0"}]}}),
        ),
    );

    let m = format!("{Q}login");
    let got = t.call("p10phone", &m, &json!({"call_queue_account_id": "all"}))?;
    t.expect(
        "login: account_id required",
        got,
        -1,
        &err(&m, 10011, &not_found("account_id")),
    );
    let got = t.call("p10phone", &m, &json!({"account_id": "1001"}))?;
    t.expect(
        "login: call_queue_account_id required",
        got,
        -1,
        &err(&m, 10011, &not_found("call_queue_account_id")),
    );
    let mark = t.log().mark();
    let got = t.call(
        "p10phone",
        &m,
        &json!({"account_id": "1001", "call_queue_account_id": "ALL"}),
    )?;
    t.expect("login all", got, 0, &ok(&m, success()));
    sleep(1.0);
    let log = t.log().since(mark);
    t.c().contains(
        "login: failure only logged",
        &log,
        &["Failed to add queue member Local/ghost@p10test to queue p10ghost"],
    );
    let show = t.cli("queue show");
    let re = Regex::new(r"Alice P10 \(Local/agent@p10test\).*\(dynamic\)").expect("regex");
    let found = re.is_match(&show);
    t.c()
        .check("login: QueueAdd with member name", found, &show);
    let found = show
        .split_once("p10support")
        .is_some_and(|(_, rest)| rest.contains("Local/1001@p10test"));
    t.c().check("login: login_exten dialed", found, &show);

    let m = format!("{Q}pause");
    let got = t.call(
        "p10phone",
        &m,
        &json!({"account_id": "1001", "call_queue_account_id": "p10sales"}),
    )?;
    t.expect(
        "pause: reason required",
        got,
        -1,
        &err(&m, 10011, &not_found("reason")),
    );
    let got = t.call(
        "p10phone",
        &m,
        &json!({"account_id": "1001", "reason": "Lunch", "call_queue_account_id": "p10sales"}),
    )?;
    t.expect("pause p10sales", got, 0, &ok(&m, success()));
    let show = t.cli("queue show p10sales");
    t.c()
        .contains("pause: reason sent", &show, &["paused:Lunch"]);
    let m = format!("{Q}getList");
    let (rc, body) = t.call("p10phone", &m, &json!({"account_id": "1001"}))?;
    let good = t.rc_ok(rc, 0)
        && body.contains(r#"{"name":"p10sales","account_id":"p10sales","paused_time":"1","loggedin_status":"logged_in","total_members":"1","members_logged_in":"0","callers_waiting":"0"}"#);
    t.c().check("getList: paused member", good, &body);
    let m = format!("{Q}resume");
    let got = t.call("p10phone", &m, &json!({"account_id": "1001"}))?;
    t.expect(
        "resume: call_queue_account_id required",
        got,
        -1,
        &err(&m, 10011, &not_found("call_queue_account_id")),
    );
    let got = t.call(
        "p10phone",
        &m,
        &json!({"account_id": "1001", "call_queue_account_id": "p10sales"}),
    )?;
    t.expect("resume p10sales", got, 0, &ok(&m, success()));
    let show = t.cli("queue show p10sales");
    t.c().lacks("resume: unpaused", &show, &["paused"]);

    // One caller connected to the agent, one waiting.
    t.cli("channel originate Local/caller@p10test application Wait 100");
    sleep(2.0);
    t.cli("channel originate Local/caller2@p10test application Wait 100");
    sleep(2.0);
    let m = format!("{Q}getTodaysStatus");
    let (rc, body) = t.call(
        "p10phone",
        &m,
        &json!({"account_id": "1001", "call_queue_account_id": "P10SALES"}),
    )?;
    let good = todays_status_ok(t, rc, &body);
    t.c().check(
        "getTodaysStatus: details with a call and a waiting caller",
        good,
        &body,
    );
    let got = t.call(
        "p10phone",
        &m,
        &json!({"account_id": "1001", "call_queue_account_id": "p10support"}),
    )?;
    t.expect(
        "getTodaysStatus: overview permission",
        got,
        0,
        &ok(
            &m,
            json!({"callQueue": {
                "account_id": "p10support", "name": "p10support", "overview": {"total_members": "1", "logged_in_count": "1", "members_on_call": "0",
                "callers_waiting": "0", "total_calls": "0", "completed_calls_today": "0", "abandoned_calls": "0", "redirected_calls": "0",
                "longest_queue_length": "0", "avg_entry_position": "0"}, "my_status": {"login_status": ""}}}),
        ),
    );
    // No answer at all; a phone gets the request handler's error for an
    // empty answer instead.
    let none = if t.via() == Via::Hook {
        String::new()
    } else {
        err(&m, 10002, "Error parsing request: empty response body ")
    };
    let got = t.call(
        "p10phone",
        &m,
        &json!({"account_id": "1001", "call_queue_account_id": "nosuch"}),
    )?;
    t.expect("getTodaysStatus: no application, no answer", got, 0, &none);
    let got = t.call(
        "p10phone",
        &m,
        &json!({"account_id": "1001", "call_queue_account_id": "p10ghost"}),
    )?;
    t.expect("getTodaysStatus: no queue, no answer", got, 0, &none);
    let got = t.call("p10phone", &m, &json!({"account_id": "1001"}))?;
    t.expect(
        "getTodaysStatus: call_queue_account_id required",
        got,
        -1,
        &err(&m, 10011, &not_found("call_queue_account_id")),
    );
    let (_, body) = t.call(
        "p10phone",
        &format!("{Q}getList"),
        &json!({"account_id": "1001"}),
    )?;
    t.c().contains(
        "getList: callers waiting",
        &body,
        &[r#""callers_waiting":"1""#],
    );

    // Abandon the waiting caller, complete the call.
    let chans = t.cli("core show channels concise");
    for line in chans.lines() {
        if line.starts_with("Local/caller2@p10test") && line.contains(";2!") {
            let chan = line.split('!').next().unwrap_or_default();
            t.cli(&format!("channel request hangup {chan}"));
        }
    }
    sleep(1.0);
    t.cli("channel request hangup all");
    sleep(1.0);
    let (_, body) = t.call(
        "p10phone",
        &m,
        &json!({"account_id": "1001", "call_queue_account_id": "p10sales"}),
    )?;
    t.c().contains(
        "getTodaysStatus: completed and abandoned",
        &body,
        &[r#""total_calls":"2","completed_calls_today":"1","abandoned_calls":"1""#],
    );

    let m = format!("{Q}logout");
    let got = t.call(
        "p10phone2",
        &m,
        &json!({"account_id": "1002", "call_queue_account_id": "p10static"}),
    )?;
    t.expect("logout: static member stays", got, 0, &ok(&m, success()));
    let show = t.cli("queue show p10static");
    t.c()
        .contains("logout: static member still there", &show, &["Static Bob"]);
    let got = t.call(
        "p10phone",
        &m,
        &json!({"account_id": "1001", "call_queue_account_id": "all"}),
    )?;
    t.expect("logout all", got, 0, &ok(&m, success()));
    sleep(1.0);
    let show = t.cli("queue show");
    t.c().lacks(
        "logout: QueueRemove and logout_exten",
        &show,
        &["Local/agent@p10test", "Local/1001@p10test"],
    );
    let mark = t.log().mark();
    t.call(
        "p10phone",
        &format!("{Q}pause"),
        &json!({"account_id": "1001", "reason": "x", "call_queue_account_id": "p10sales"}),
    )?;
    let logged = t.logged(
        mark,
        "Failed to pause queue member Local/agent@p10test on queue p10sales",
    );
    t.c().check("pause: failure only logged", logged, "");
    Ok(())
}

pub fn phonebook(t: &mut T) -> Result<()> {
    let m = "switchvox.users.phonebooks.entries.add";
    let full = json!({"account_id": "1001", "phonebook_id": "coworkers", "extension": "1005", "name": "Dave & <Co>"});
    let with = |k: &str, v: &str| -> Value {
        let mut p = full.clone();
        p[k] = json!(v);
        p
    };
    for key in ["account_id", "phonebook_id", "extension", "name"] {
        let p: Map<String, Value> = full
            .as_object()
            .expect("object")
            .iter()
            .filter(|(k, _)| *k != key)
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let got = t.call("p10phone", m, &Value::Object(p))?;
        t.expect(
            &format!("phonebook: {key} required"),
            got,
            -1,
            &err(m, 10011, &not_found(key)),
        );
    }
    let got = t.call("p10phone", m, &with("extension", "1002"))?;
    t.expect(
        "phonebook: entry exists",
        got,
        -1,
        &err(
            m,
            15688,
            "Phonebook entry already exists: contact_list_entry_exists ",
        ),
    );
    let got = t.call("p10phone", m, &full)?;
    t.expect("phonebook: add", got, 0, &ok(m, success()));
    let mut p = with("phonebook_id", "empty");
    p["extension"] = json!("1006");
    p["name"] = json!("Erin");
    let got = t.call("p10phone", m, &p)?;
    t.expect("phonebook: add to an empty list", got, 0, &ok(m, success()));
    let mut p = with("phonebook_id", "second");
    p["extension"] = json!("1007");
    p["name"] = json!("Frank");
    let got = t.call("p10phone", m, &p)?;
    t.expect("phonebook: second file", got, 0, &ok(m, success()));
    let got = t.call("p10phone", m, &with("phonebook_id", "nosuch"))?;
    t.expect(
        "phonebook: no such list",
        got,
        -1,
        &err(m, 51141, "Invalid phonebook_id: contact not found "),
    );
    let dir = files_dir(t.inst());
    let doc = std::fs::read_to_string(dir.join("p10contacts.xml")).unwrap_or_default();
    t.c().contains(
        "phonebook: contact written",
        &doc,
        &[concat!(
            r#"<contact first_name="Dave &amp; &lt;Co&gt;" last_name="" contact_type="sip|external" subscribe_to="1005">"#,
            r#"<numbers><number dial="1005" label="Extension" primary="1"/></numbers></contact></contacts>"#
        )],
    );
    let second = dir.join("p10contacts2.xml");
    std::fs::set_permissions(&second, std::fs::Permissions::from_mode(0o444))?;
    let mut p = with("phonebook_id", "second");
    p["extension"] = json!("1009");
    let got = t.call("p10phone", m, &p);
    std::fs::set_permissions(&second, std::fs::Permissions::from_mode(0o644))?;
    t.expect(
        "phonebook: unwritable file",
        got?,
        -1,
        &err(
            m,
            15688,
            "Phonebook entry already exists: contact_list_entry_add ",
        ),
    );
    Ok(())
}

/// Starts the test phone; `None` (and a failed check) unless the module
/// takes it for a Digium phone.
fn digium_phone(t: &mut T) -> Result<Option<PhoneLog>> {
    let phone = PhoneLog::start(t)?;
    let out = t.cli("dpmadev pjsip isdphone 1001");
    if !out.contains("= 1") {
        t.c()
            .check("phone registered as a Digium phone", false, out);
        phone.stop();
        return Ok(None);
    }
    Ok(Some(phone))
}

pub fn parking(t: &mut T) -> Result<()> {
    let Some(mut phone) = digium_phone(t)? else {
        return Ok(());
    };
    let m = "switchvox.users.parkingLots.getList";
    let lots = json!({"parking_lots": {"parking_lot": [
        {"account_id": "default", "parked_calls": {"parked_call": []}, "parking_lot_stop": "720", "timeout": "45", "parking_lot_start": "701"},
        {"account_id": "p10lot", "parked_calls": {"parked_call": []}, "parking_lot_stop": "810", "timeout": "300", "parking_lot_start": "801"}]}});
    let got = t.call("p10phone", m, &json!({}))?;
    t.expect("parkingLots.getList: empty lots", got, 0, &ok(m, lots));
    t.cli("channel originate Local/parklot@p10test application Wait 100");
    t.cli("channel originate Local/park@p10test application Wait 100");
    sleep(3.0);
    let (rc, body) = t.call("p10phone", m, &json!({}))?;
    let good = serde_json::from_str::<Value>(&body).is_ok_and(|doc| {
        let got = &doc["response"]["result"]["parking_lots"]["parking_lot"];
        let call0 = &got[1]["parked_calls"]["parked_call"][0];
        t.rc_ok(rc, 0)
            && got[0]["parked_calls"]["parked_call"] == json!([])
            && keys(call0)
                == [
                    "from_caller_id_name",
                    "from_caller_id_number",
                    "duration",
                    "lotnum",
                    "current_call_id",
                ]
            && call0["from_caller_id_name"] == "Lot Caller"
            && call0["from_caller_id_number"] == "5554000"
            && call0["lotnum"] == "801"
            && call0["current_call_id"]
                .as_str()
                .is_some_and(|s| s.starts_with("Local/parklot@p10test-"))
    });
    t.c().check(
        "parkingLots.getList: only the lots of the phone's parking application",
        good,
        &body,
    );
    let (rc, body) = t.call("p10phone2", m, &json!({}))?;
    let good =
        t.rc_ok(rc, 0) && body.contains(r#""lotnum":"701""#) && body.contains(r#""lotnum":"801""#);
    t.c().check(
        "parkingLots.getList: no parking application sees every lot",
        good,
        &body,
    );
    let log = phone.text();
    let good = log.contains("X-Event-Name: digium.parkingLot.parked")
        && log.contains(r#"body: {"lotnumber":"701"}"#);
    t.c()
        .check("parked call event sent to the parker's phone", good, &log);
    for args in ["PJSIP/1001 705 1", "SIP/1001 706", "PJSIP/1002 707"] {
        t.cli(&format!("dpmadev calls parked {args}"));
    }
    sleep(1.0);
    let log = phone.text();
    t.c().check(
        "parked call event: only PARKED_CALL, only PJSIP",
        log.matches("digium.parkingLot.parked").count() == 1,
        &log,
    );
    t.cli("channel request hangup all");
    phone.stop();
    Ok(())
}

pub fn recording(t: &mut T) -> Result<()> {
    let result = record(t);
    t.reset()?;
    result
}

fn record(t: &mut T) -> Result<()> {
    let Some(mut phone) = digium_phone(t)? else {
        return Ok(());
    };
    t.cli("channel originate PJSIP/1001 application Wait 30");
    sleep(2.0);
    let re = Regex::new(r"INVITE call-id=(\S+)").expect("regex");
    let log = phone.text();
    let Some(cid) = re.captures_iter(&log).last().map(|c| c[1].to_string()) else {
        t.c()
            .check("recording: call to PJSIP/1001 answered", false, &log);
        phone.stop();
        return Ok(());
    };
    let m = "switchvox.users.currentCalls.startRecording";
    let s = "switchvox.users.currentCalls.stopRecording";
    let p = json!({"requested_account_id": "1001", "call_id": cid});
    let not_permitted =
        |what: &str| format!("Your account is not permitted to run this action: {what} ");
    let got = t.call("p10phone", m, &json!({"call_id": cid}))?;
    t.expect(
        "startRecording: requested_account_id required",
        got,
        -1,
        &err(m, 10011, &not_found("requested_account_id")),
    );
    let got = t.call("p10phone", m, &json!({"requested_account_id": "1001"}))?;
    t.expect(
        "startRecording: call_id required",
        got,
        -1,
        &err(m, 10011, &not_found("call_id")),
    );
    let got = t.call(
        "p10phone",
        m,
        &json!({"requested_account_id": "1002", "call_id": cid}),
    )?;
    t.expect(
        "startRecording: line without mailbox",
        got,
        -1,
        &err(m, 27168, &not_permitted("mailbox")),
    );
    let got = t.call(
        "p10phone",
        m,
        &json!({"requested_account_id": "1001", "call_id": "nope"}),
    )?;
    t.expect(
        "startRecording: no such call",
        got,
        -1,
        &err(m, 27168, &not_permitted("channel")),
    );
    let got = t.call("p10phone", s, &p)?;
    t.expect(
        "stopRecording: nothing recording",
        got,
        -1,
        &err(s, 27168, &not_permitted("MixMonitor")),
    );
    let mark = t.log().mark();
    // The original reads "Success" into an 8-byte buffer and always reports
    // an error; dpma-rs reports the success (plan section 8, item 10).
    let got = t.call("p10phone", m, &p)?;
    t.expect("startRecording", got, 0, &ok(m, success()));
    let chans = t.cli("core show channels concise");
    let chan = chans
        .lines()
        .find(|l| l.starts_with("PJSIP/1001-"))
        .and_then(|l| l.split('!').next())
        .map(str::to_string);
    let running = chan.is_some_and(|c| {
        t.cli(&format!("core show channel {c}"))
            .contains("MIXMONITOR_FILENAME")
    });
    t.c()
        .check("startRecording: MixMonitor running", running, &chans);
    sleep(1.0);
    let log = t.log().since(mark);
    t.c().lacks(
        "startRecording: no failure logged",
        &log,
        &["Failed to start MixMonitor"],
    );
    let plog = phone.text();
    t.c().check(
        "startRecording: INFO sent",
        plog.matches("X-Event-Type: digium.startRecording.success")
            .count()
            == 1,
        &plog,
    );
    let got = t.call("p10phone", s, &p)?;
    t.expect("stopRecording", got, 0, &ok(s, success()));
    sleep(1.0);
    let plog = phone.text();
    t.c().contains(
        "stopRecording: INFO sent",
        &plog,
        &["X-Event-Type: digium.stopRecording.success"],
    );
    let x = format!(
        "<parameters><requested_account_id>1001</requested_account_id><call_id>{cid}</call_id></parameters>"
    );
    let got = t.call_xml("p10phone", m, &x)?;
    t.expect("startRecording (XML)", got, 0, &xml_ok(m));
    sleep(1.0);
    let plog = phone.text();
    t.c().check(
        "startRecording (XML): INFO sent",
        plog.matches("X-Event-Type: digium.startRecording.success")
            .count()
            == 2,
        &plog,
    );
    let got = t.call_xml("p10phone", s, &x)?;
    t.expect("stopRecording (XML)", got, 0, &xml_ok(s));
    let got = t.call_xml("p10phone", s, &x)?;
    t.expect(
        "stopRecording (XML): nothing recording",
        got,
        -1,
        &xml_err(s, 27168, "Your account is not permitted to run this action"),
    );
    let got = t.call_xml(
        "p10phone",
        s,
        "<parameters><requested_account_id>1001</requested_account_id></parameters>",
    )?;
    t.expect(
        "stopRecording (XML): call_id required",
        got,
        -1,
        &xml_err(s, 10011, "Parameters not found"),
    );
    let got = t.call_xml(
        "p10phone",
        m,
        "<parameters><requested_account_id>1002</requested_account_id></parameters>",
    )?;
    t.expect(
        "startRecording (XML): mailbox before call_id",
        got,
        -1,
        &xml_err(m, 27168, "Your account is not permitted to run this action"),
    );
    t.cli("channel request hangup all");
    phone.stop();
    Ok(())
}
