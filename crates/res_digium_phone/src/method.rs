//! Phone method registries (phone_method.c).
//!
//! Three independent, case-insensitive registries keyed by method name:
//!
//! * XML methods (container at 0x5f4e68),
//! * JSON methods (0x5f4e58), and
//! * AMI methods (0x5f4e60): names registered by AMI clients with
//!   `DPMAMessageRegister`; requests for them are forwarded to AMI as
//!   `DPMAMessage` events.
//!
//! Registering a name replaces an earlier registration of the same name
//! in the same registry only.  (The original's `__phone_method_unregister`
//! also unlinks the found object from the other containers, but that
//! object only ever lives in its own container, so those unlinks never
//! remove anything.)  An XML or JSON method therefore does not remove an
//! AMI registration of the same name; it shadows it, because
//! `handle_request_xml` / `handle_request_json` look in their own
//! registry before the AMI one.
//!
//! Owner: P3 "request" (wave 1).

use crate::session::Transaction;
use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

/// Context of one method invocation.
pub struct MethodCall {
    /// Name of the authenticated phone (`[phone]` section) making the
    /// request.
    pub phone: String,
    /// Method name as requested.
    pub method: String,
    /// The transaction, when invoked for a phone request (None from test
    /// hooks).
    pub tx: Option<Arc<Transaction>>,
}

/// An XML method: `params` is the `<parameters>` element as XML text;
/// the response document is appended to `out`.  Returns 0 or a request
/// error code (`dpma_proto::errors::request`).
pub type XmlMethod = fn(call: &MethodCall, params: &str, out: &mut String) -> i32;

/// A JSON method: `params` is the request's `"parameters"` value.
pub type JsonMethod = fn(call: &MethodCall, params: &serde_json::Value, out: &mut String) -> i32;

/// Which registry (the original's `phone_method_find` kind argument).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Xml = 0,
    Json = 1,
    Ami = 2,
}

/// One registry: lower-cased name to (name as registered, value).
type Registry<T> = BTreeMap<String, (String, T)>;

struct Registries {
    xml: Registry<XmlMethod>,
    json: Registry<JsonMethod>,
    ami: Registry<()>,
}

/// None while the module is not loaded (the containers do not exist).
static REGISTRIES: RwLock<Option<Registries>> = RwLock::new(None);

fn key(name: &str) -> String {
    name.to_ascii_lowercase()
}

/// `phone_method_load` (FUN_00178c10): create the three registries.
pub fn load() -> Result<(), ()> {
    let mut g = REGISTRIES.write().unwrap();
    if g.is_some() {
        // The original's message has no trailing newline.
        dpma_ast::log::log(
            dpma_ast::log::custom_level(),
            file!(),
            line!(),
            "load",
            "Attempted to allocate phone method containers, but one or more is already initialized.",
        );
        return Err(());
    }
    *g = Some(Registries { xml: BTreeMap::new(), json: BTreeMap::new(), ami: BTreeMap::new() });
    Ok(())
}

/// `phone_method_unload` (FUN_00178dd0): drop the registries and every
/// registration in them.
pub fn unload() {
    REGISTRIES.write().unwrap().take();
}

/// `__phone_method_register`: fails for an empty name or when the
/// registries do not exist.
fn register<T>(name: &str, value: T, pick: fn(&mut Registries) -> &mut Registry<T>) -> Result<(), ()> {
    if name.is_empty() {
        return Err(());
    }
    let mut g = REGISTRIES.write().unwrap();
    let regs = g.as_mut().ok_or(())?;
    pick(regs).insert(key(name), (name.to_string(), value));
    Ok(())
}

fn unregister<T>(name: &str, pick: fn(&mut Registries) -> &mut Registry<T>) {
    if let Some(regs) = REGISTRIES.write().unwrap().as_mut() {
        pick(regs).remove(&key(name));
    }
}

pub fn register_xml(name: &str, f: XmlMethod) -> Result<(), ()> {
    register(name, f, |r| &mut r.xml)
}

pub fn register_json(name: &str, f: JsonMethod) -> Result<(), ()> {
    register(name, f, |r| &mut r.json)
}

/// Register a name handled by AMI (`DPMAMessageRegister`).
pub fn register_ami(name: &str) -> Result<(), ()> {
    register(name, (), |r| &mut r.ami)
}

pub fn unregister_xml(name: &str) {
    unregister(name, |r| &mut r.xml)
}

pub fn unregister_json(name: &str) {
    unregister(name, |r| &mut r.json)
}

pub fn unregister_ami(name: &str) {
    unregister(name, |r| &mut r.ami)
}

pub fn find_xml(name: &str) -> Option<XmlMethod> {
    REGISTRIES.read().unwrap().as_ref()?.xml.get(&key(name)).map(|(_, f)| *f)
}

pub fn find_json(name: &str) -> Option<JsonMethod> {
    REGISTRIES.read().unwrap().as_ref()?.json.get(&key(name)).map(|(_, f)| *f)
}

pub fn is_ami(name: &str) -> bool {
    REGISTRIES
        .read()
        .unwrap()
        .as_ref()
        .is_some_and(|r| r.ami.contains_key(&key(name)))
}

/// The names registered in one registry, as registered (sorted case
/// insensitively).  Empty when the registries do not exist.
pub fn names(kind: Kind) -> Vec<String> {
    let g = REGISTRIES.read().unwrap();
    let Some(r) = g.as_ref() else {
        return Vec::new();
    };
    match kind {
        Kind::Xml => r.xml.values().map(|(n, _)| n.clone()).collect(),
        Kind::Json => r.json.values().map(|(n, _)| n.clone()).collect(),
        Kind::Ami => r.ami.values().map(|(n, _)| n.clone()).collect(),
    }
}

#[cfg(feature = "devtest")]
mod devtest {
    use super::*;
    use dpma_ast::cli::{CliArgs, CliCommand, CliResult};

    fn kind_of(s: &str) -> Option<Kind> {
        match s.to_ascii_lowercase().as_str() {
            "xml" => Some(Kind::Xml),
            "json" => Some(Kind::Json),
            "ami" => Some(Kind::Ami),
            _ => None,
        }
    }

    fn list(a: &CliArgs) -> CliResult {
        if a.argc() != 3 {
            return CliResult::ShowUsage;
        }
        if REGISTRIES.read().unwrap().is_none() {
            a.out("Method registries are not loaded\n");
            return CliResult::Success;
        }
        for (label, kind) in [("XML", Kind::Xml), ("JSON", Kind::Json), ("AMI", Kind::Ami)] {
            let names = names(kind);
            a.out(&format!("{} methods ({}):\n", label, names.len()));
            for n in names {
                a.out(&format!("  {}\n", n));
            }
        }
        CliResult::Success
    }

    /// Test methods registered by `dpmadev method register`: they echo the
    /// call back so the CLI can see which registration answered.
    fn test_xml(call: &MethodCall, params: &str, out: &mut String) -> i32 {
        out.push_str(&format!(
            "<response method=\"{}\"><result phone=\"{}\" registry=\"xml\">{}</result></response>",
            call.method, call.phone, params
        ));
        0
    }

    fn test_json(call: &MethodCall, params: &serde_json::Value, out: &mut String) -> i32 {
        let v = serde_json::json!({
            "response": {"method": call.method, "result": {"phone": call.phone, "registry": "json", "parameters": params}}
        });
        out.push_str(&dpma_proto::json::dump(&v));
        0
    }

    fn register_cmd(a: &CliArgs) -> CliResult {
        if a.argc() != 5 {
            return CliResult::ShowUsage;
        }
        let Some(kind) = kind_of(&a.argv[3]) else {
            return CliResult::ShowUsage;
        };
        let name = &a.argv[4];
        let res = match kind {
            Kind::Xml => register_xml(name, test_xml),
            Kind::Json => register_json(name, test_json),
            Kind::Ami => register_ami(name),
        };
        a.out(&format!(
            "register {:?} '{}': {}\n",
            kind,
            name,
            if res.is_ok() { "ok" } else { "failed" }
        ));
        CliResult::Success
    }

    fn unregister_cmd(a: &CliArgs) -> CliResult {
        if a.argc() != 5 {
            return CliResult::ShowUsage;
        }
        let Some(kind) = kind_of(&a.argv[3]) else {
            return CliResult::ShowUsage;
        };
        let name = &a.argv[4];
        match kind {
            Kind::Xml => unregister_xml(name),
            Kind::Json => unregister_json(name),
            Kind::Ami => unregister_ami(name),
        }
        a.out(&format!("unregister {:?} '{}': done\n", kind, name));
        CliResult::Success
    }

    /// Look a method up the way the request handlers do: own registry
    /// first, then AMI.
    fn find_cmd(a: &CliArgs) -> CliResult {
        if a.argc() != 5 {
            return CliResult::ShowUsage;
        }
        let name = &a.argv[4];
        let found = match kind_of(&a.argv[3]) {
            Some(Kind::Xml) => find_xml(name).is_some(),
            Some(Kind::Json) => find_json(name).is_some(),
            _ => return CliResult::ShowUsage,
        };
        let what = if found {
            "built-in method"
        } else if is_ami(name) {
            "forwarded to AMI (DPMAMessage)"
        } else {
            "not found"
        };
        a.out(&format!("{} '{}': {}\n", a.argv[3].to_ascii_uppercase(), name, what));
        CliResult::Success
    }

    fn call_cmd(a: &CliArgs) -> CliResult {
        if a.argc() < 6 {
            return CliResult::ShowUsage;
        }
        let phone = a.argv[3].clone();
        let method = a.argv[4].clone();
        let text = a.argv[5..].join(" ");
        let params: serde_json::Value = match serde_json::from_str(&text) {
            Ok(v) => v,
            Err(e) => {
                a.out(&format!("Invalid JSON parameters: {}\n", e));
                return CliResult::Success;
            }
        };
        let mut out = String::new();
        match find_json(&method) {
            Some(f) => {
                let call = MethodCall { phone, method: method.clone(), tx: None };
                let code = f(&call, &params, &mut out);
                a.out(&format!("Return code: {}\n", code));
                if out.is_empty() {
                    crate::request::error_response_json(
                        &mut out,
                        &method,
                        dpma_proto::errors::request::PARSE,
                        "empty response body",
                    );
                    a.out("(empty response body; the handler would answer with:)\n");
                }
            }
            None => {
                let ami = is_ami(&method);
                a.out(&format!(
                    "No JSON method '{}'{}\n",
                    method,
                    if ami { "; registered by AMI (would raise DPMAMessage)" } else { "" }
                ));
                if ami {
                    return CliResult::Success;
                }
                crate::request::error_response_json(
                    &mut out,
                    &method,
                    dpma_proto::errors::request::METHOD_NOT_FOUND,
                    &method,
                );
            }
        }
        a.out(&format!("{}\n", out));
        CliResult::Success
    }

    pub fn commands() -> Vec<CliCommand> {
        vec![
            CliCommand {
                command: "dpmadev method list",
                summary: "List the XML, JSON, and AMI method registries",
                usage: "Usage: dpmadev method list\n",
                exec: list,
                complete: None,
            },
            CliCommand {
                command: "dpmadev method register",
                summary: "Register a test method",
                usage: "Usage: dpmadev method register xml|json|ami <name>\n       Registers a test method that echoes its call (xml, json) or an AMI name.\n",
                exec: register_cmd,
                complete: None,
            },
            CliCommand {
                command: "dpmadev method unregister",
                summary: "Unregister a method",
                usage: "Usage: dpmadev method unregister xml|json|ami <name>\n",
                exec: unregister_cmd,
                complete: None,
            },
            CliCommand {
                command: "dpmadev method find",
                summary: "Look up a method as an XML or JSON request would",
                usage: "Usage: dpmadev method find xml|json <name>\n",
                exec: find_cmd,
                complete: None,
            },
            CliCommand {
                command: "dpmadev method call",
                summary: "Invoke a JSON method for a phone",
                usage: "Usage: dpmadev method call <phone> <method> <json parameters>\n",
                exec: call_cmd,
                complete: None,
            },
        ]
    }
}

/// Test hooks (feature "devtest"): list the registries, register test
/// methods, look methods up, and invoke a JSON method for a phone.
#[cfg(feature = "devtest")]
pub fn devtest_commands() -> Vec<dpma_ast::cli::CliCommand> {
    devtest::commands()
}
