//! Tests for the URI parser.  Most cases are chan_sip's own unit tests
//! (reqresp_parser.c `sip_parse_uri_full_test`, `sip_parse_uri_test`,
//! `get_calleridname_test`, `get_in_brackets_test`,
//! `parse_name_andor_addr_test`, `sip_uri_cmp_test`), less the tel: URI
//! cases (this copy of the parser has no tel: handling).

use super::*;
use crate::testlog;

/// The parser's results as text (every input here is ASCII).
trait AsStr {
    fn as_str(&self) -> &str;
}

impl AsStr for Vec<u8> {
    fn as_str(&self) -> &str {
        std::str::from_utf8(self).unwrap()
    }
}


struct Full {
    desc: &'static str,
    uri: &'static str,
    user: &'static str,
    pass: &'static str,
    hostport: &'static str,
    headers: &'static str,
    residue: &'static str,
    transport: &'static str,
    lr: bool,
}

#[test]
fn chan_sip_parse_uri_full() {
    let cases = [
        Full {
            desc: "no headers",
            uri: "sip:user:secret@host:5060;param=discard;transport=tcp;param2=residue",
            user: "user",
            pass: "secret",
            hostport: "host:5060",
            headers: "",
            residue: "param2=residue",
            transport: "tcp",
            lr: false,
        },
        Full {
            desc: "with headers",
            uri: "sip:user:secret@host:5060;param=discard;transport=tcp;param2=discard2?header=blah&header2=blah2;param3=residue",
            user: "user",
            pass: "secret",
            hostport: "host:5060",
            headers: "header=blah&header2=blah2",
            residue: "param3=residue",
            transport: "tcp",
            lr: false,
        },
        Full {
            desc: "difficult user",
            uri: "sip:-_.!~*'()&=+$,;?/:secret@host:5060;transport=tcp",
            user: "-_.!~*'()&=+$,;?/",
            pass: "secret",
            hostport: "host:5060",
            headers: "",
            residue: "",
            transport: "tcp",
            lr: false,
        },
        Full {
            desc: "difficult pass",
            uri: "sip:user:-_.!~*'()&=+$,@host:5060;transport=tcp",
            user: "user",
            pass: "-_.!~*'()&=+$,",
            hostport: "host:5060",
            headers: "",
            residue: "",
            transport: "tcp",
            lr: false,
        },
        Full {
            desc: "difficult host",
            uri: "sip:user:secret@1-1.a-1.:5060;transport=tcp",
            user: "user",
            pass: "secret",
            hostport: "1-1.a-1.:5060",
            headers: "",
            residue: "",
            transport: "tcp",
            lr: false,
        },
        Full {
            desc: "difficult params near transport",
            uri: "sip:user:secret@host:5060;-_.!~*'()[]/:&+$=-_.!~*'()[]/:&+$;transport=tcp",
            user: "user",
            pass: "secret",
            hostport: "host:5060",
            headers: "",
            residue: "",
            transport: "tcp",
            lr: false,
        },
        Full {
            desc: "difficult params near headers",
            uri: "sip:user:secret@host:5060;-_.!~*'()[]/:&+$=-_.!~*'()[]/:&+$?header=blah&header2=blah2;-_.!~*'()[]/:&+$=residue",
            user: "user",
            pass: "secret",
            hostport: "host:5060",
            headers: "header=blah&header2=blah2",
            residue: "-_.!~*'()[]/:&+$=residue",
            transport: "",
            lr: false,
        },
        Full {
            desc: "lr parameter",
            uri: "sip:user:secret@host:5060;param=discard;lr?header=blah",
            user: "user",
            pass: "secret",
            hostport: "host:5060",
            headers: "header=blah",
            residue: "",
            transport: "",
            lr: true,
        },
        Full {
            desc: "alternative lr parameter",
            uri: "sip:user:secret@host:5060;param=discard;lr=yes?header=blah",
            user: "user",
            pass: "secret",
            hostport: "host:5060",
            headers: "header=blah",
            residue: "",
            transport: "",
            lr: true,
        },
        Full {
            desc: "no lr parameter",
            uri: "sip:user:secret@host:5060;paramlr=lr;lr=no;lr=off;lr=0;lr=;=lr;lrextra;lrparam2=lr?header=blah",
            user: "user",
            pass: "secret",
            hostport: "host:5060",
            headers: "header=blah",
            residue: "",
            transport: "",
            lr: false,
        },
    ];
    for c in cases {
        let r = parse_uri_full(c.uri, Some("sip:,sips:,tel:"), ParseOpts::ALL);
        assert!(!r.error, "{}", c.desc);
        assert_eq!(r.user.as_str(), c.user, "{}", c.desc);
        assert_eq!(r.pass.as_str(), c.pass, "{}", c.desc);
        assert_eq!(r.hostport.as_str(), c.hostport, "{}", c.desc);
        assert_eq!(r.headers.as_str(), c.headers, "{}", c.desc);
        assert_eq!(r.residue.as_str(), c.residue, "{}", c.desc);
        assert_eq!(r.params.transport.as_str(), c.transport, "{}", c.desc);
        assert_eq!(r.params.lr, c.lr, "{}", c.desc);
        assert_eq!(r.params.user.as_str(), "", "{}", c.desc);
    }
}

#[test]
fn chan_sip_parse_uri() {
    const S: Option<&str> = Some("sip:,sips:");
    let tail = "?headers=%40%40testblah&headers2=blah%20blah";

    let r = parse_uri("sip:name@host", S, true, true);
    assert_eq!((r.error, r.user.as_str(), r.pass.as_str(), r.hostport.as_str(), r.params.transport.as_str()), (false, "name", "", "host", ""));
    let r = parse_uri("sip:name@host;transport=tcp", S, true, true);
    assert_eq!((r.error, r.user.as_str(), r.pass.as_str(), r.hostport.as_str(), r.params.transport.as_str()), (false, "name", "", "host", "tcp"));
    let r = parse_uri("sip:name:secret@host;transport=tcp", S, true, true);
    assert_eq!((r.error, r.user.as_str(), r.pass.as_str(), r.hostport.as_str(), r.params.transport.as_str()), (false, "name", "secret", "host", "tcp"));
    let u4 = format!("sip:name:secret@host:port;transport=tcp{}", tail);
    let r = parse_uri(&u4, S, true, true);
    assert_eq!((r.error, r.user.as_str(), r.pass.as_str(), r.hostport.as_str(), r.params.transport.as_str()), (false, "name", "secret", "host:port", "tcp"));
    // Test 5: empty input.
    let r = parse_uri("", S, true, true);
    assert!(r.error);
    assert_eq!((r.user.as_str(), r.pass.as_str(), r.hostport.as_str(), r.params.transport.as_str()), ("", "", "", ""));
    // Test 6: no outputs.
    assert!(!parse_uri(&u4, S, false, false).error);
    // Test 7: without pass, the user keeps its secret.
    let r = parse_uri(&u4, S, false, true);
    assert_eq!((r.error, r.user.as_str(), r.hostport.as_str()), (false, "name:secret", "host:port"));
    let r = parse_uri("sip:host", S, true, true);
    assert_eq!((r.error, r.user.as_str(), r.hostport.as_str()), (false, "", "host"));
    let r = parse_uri(format!("sip:host:port;transport=tcp{}", tail), S, true, true);
    assert_eq!((r.error, r.user.as_str(), r.pass.as_str(), r.hostport.as_str(), r.params.transport.as_str()), (false, "", "", "host:port", "tcp"));
    // Tests 10 and 11: a missing scheme is an error, but the parts are
    // still filled in (and the original logs it).
    let (r, logs) = testlog::capture(|| parse_uri(format!("host:port;transport=tcp{}", tail), S, true, true));
    assert_eq!((r.error, r.user.as_str(), r.pass.as_str(), r.hostport.as_str(), r.params.transport.as_str()), (true, "", "", "host:port", "tcp"));
    assert_eq!(logs, vec![format!("No supported scheme found in 'host:port;transport=tcp{}' using the scheme[s] sip:,sips:\n", tail)]);
    let r = parse_uri("host", S, true, true);
    assert_eq!((r.error, r.user.as_str(), r.pass.as_str(), r.hostport.as_str(), r.params.transport.as_str()), (true, "", "", "host", ""));
    let r = parse_uri(format!("sip:name:secret@host:port;transport=tcp{};lr", tail), S, true, true);
    assert_eq!((r.error, r.user.as_str(), r.pass.as_str(), r.hostport.as_str(), r.params.transport.as_str()), (false, "name", "secret", "host:port", "tcp"));
}

#[test]
fn parse_uri_edge_cases() {
    // Scheme matching is case insensitive; the scheme text is removed as
    // given (without a colon, the colon stays in front of the user).
    let r = parse_uri_full("SIPS:bob@h", Some("sip:,sips:"), ParseOpts::ALL);
    assert_eq!((r.error, r.user.as_str(), r.hostport.as_str()), (false, "bob", "h"));
    let r = parse_uri_full("SIPS:bob@h", Some("sip:"), ParseOpts::ALL);
    assert_eq!((r.error, r.user.as_str(), r.pass.as_str()), (true, "SIPS", "bob"));
    let r = parse_uri_full("sip:bob@h", Some("sip,sips"), ParseOpts::ALL);
    assert_eq!((r.error, r.user.as_str(), r.pass.as_str()), (false, "", "bob"));
    // The first matching scheme wins; an empty list entry ends the list.
    let r = parse_uri_full("sips:bob@h", Some("sip,sips"), ParseOpts::ALL);
    assert_eq!((r.user.as_str(), r.pass.as_str()), ("s", "bob"));
    assert!(parse_uri_full("sip:bob@h", Some(",sip:"), ParseOpts::ALL).error);
    // No scheme list: nothing stripped.
    let r = parse_uri_full("sip:bob@h", None, ParseOpts::ALL);
    assert_eq!((r.error, r.user.as_str(), r.pass.as_str()), (false, "sip", "bob"));
    // Without hostport, nothing is split at '@', and the parameters are
    // searched for in what is left of the user after the password split.
    let o = ParseOpts { pass: true, hostport: false, params: true };
    let r = parse_uri_full("sip:bob:pw@h;transport=udp", Some("sip:"), o);
    assert_eq!((r.user.as_str(), r.pass.as_str(), r.params.transport.as_str()), ("bob", "pw@h;transport=udp", ""));
    let r = parse_uri_full("sip:bob@h;transport=udp", Some("sip:"), o);
    assert_eq!((r.user.as_str(), r.pass.as_str(), r.params.transport.as_str()), ("bob@h", "", "udp"));
    // Without params the residue is everything after the first ';'
    // ... cut at the hostport end.
    let o = ParseOpts { pass: true, hostport: true, params: false };
    let r = parse_uri_full("sip:bob@h;transport=udp;x=y", Some("sip:"), o);
    assert_eq!((r.hostport.as_str(), r.residue.as_str(), r.params.transport.as_str()), ("h", "h", ""));
    // user= method= ttl= maddr= are recognized.
    let r = parse_uri_full("sip:b@h;user=phone;method=INVITE;ttl=5;maddr=239.1.1.1;x", Some("sip:"), ParseOpts::ALL);
    assert_eq!(r.params, UriParams { transport: "".into(), user: "phone".into(), method: "INVITE".into(), ttl: "5".into(), maddr: "239.1.1.1".into(), lr: false });
    // The '=' search runs over all remaining parameters, so a parameter
    // without a value swallows the following ones (chan_sip's behavior).
    let r = parse_uri_full("sip:b@h;lr;transport=tcp", Some("sip:"), ParseOpts::ALL);
    assert_eq!((r.params.lr, r.params.transport.as_str(), r.residue.as_str()), (false, "", "lr;transport=tcp"));
    let r = parse_uri_full("sip:b@h;transport=udp;lrx;y=z", Some("sip:"), ParseOpts::ALL);
    assert_eq!((r.params.lr, r.params.transport.as_str(), r.residue.as_str()), (false, "udp", "lrx;y=z"));
    // Once no '=' is left, "lr" anything sets lr.
    let r = parse_uri_full("sip:b@h;transport=udp;lr;lr", Some("sip:"), ParseOpts::ALL);
    assert_eq!((r.params.lr, r.params.transport.as_str(), r.residue.as_str()), (true, "udp", ""));
    let r = parse_uri_full("sip:b@h;lr;x", Some("sip:"), ParseOpts::ALL);
    assert_eq!((r.params.lr, r.residue.as_str()), (true, "x"));
    let r = parse_uri_full("sip:b@h;transport=udp;lrfoo", Some("sip:"), ParseOpts::ALL);
    assert_eq!((r.params.lr, r.residue.as_str()), (true, ""));
    // Unknown trailing parameters stay in the residue.
    let r = parse_uri_full("sip:b@h;transport=udp;a=1;b=2", Some("sip:"), ParseOpts::ALL);
    assert_eq!(r.residue.as_str(), "a=1;b=2");
    // '?' in the user part is not a header separator.
    let r = parse_uri_full("sip:a?b@h?x=y", Some("sip:"), ParseOpts::ALL);
    assert_eq!((r.user.as_str(), r.hostport.as_str(), r.headers.as_str()), ("a?b", "h", "x=y"));
}

#[test]
fn chan_sip_get_calleridname() {
    let (name, rest) = get_calleridname(" \" quoted-text internal \\\" quote \"<stuff>", 40);
    assert_eq!(name.as_str(), " quoted-text internal \" quote ");
    assert_eq!(rest.as_str(), "<stuff>");
    let (name, rest) = get_calleridname(" token text with no quotes <stuff>", 40);
    assert_eq!(name.as_str(), "token text with no quotes");
    assert_eq!(rest.as_str(), "<stuff>");
    let (name, _) = get_calleridname(" \"quoted-text overflow 1234567890123456789012345678901234567890\" <stuff>", 40);
    assert_eq!(name.len(), 39);
    let (name, _) = get_calleridname(" non-quoted text overflow 1234567890123456789012345678901234567890 <stuff>", 40);
    assert_eq!(name.len(), 39);
    let input = " \"quoted-text no end <stuff>";
    let ((name, rest), logs) = testlog::capture(|| get_calleridname(input, 40));
    assert_eq!((name.as_str(), rest.as_str()), ("", input));
    assert_eq!(logs, vec!["No ending quote for display-name was found\n"]);
    let (name, rest) = get_calleridname(" sip:blah@blah", 40);
    assert_eq!((name.as_str(), rest.as_str()), ("", " sip:blah@blah"));
    let (name, rest) = get_calleridname("blah@blah", 40);
    assert_eq!((name.as_str(), rest.as_str()), ("", "blah@blah"));
    // Invalid characters are skipped; control characters in quotes too.
    let (name, _) = get_calleridname("Bob (x) <sip:b@h>", 40);
    assert_eq!(name.as_str(), "Bob x");
    let (name, _) = get_calleridname("\"a\x01b\\\nc\"<sip:b@h>", 40);
    assert_eq!(name.as_str(), "abc");
    let (name, rest) = get_calleridname("<sip:b@h>", 40);
    assert_eq!((name.as_str(), rest.as_str()), ("", "<sip:b@h>"));
}

#[test]
fn chan_sip_get_in_brackets() {
    let in_brackets = "sip:name:secret@host:port;transport=tcp?headers=testblah&headers2=blahblah";
    assert_eq!(get_in_brackets(format!("<{}>", in_brackets)).as_str(), in_brackets);
    assert_eq!(get_in_brackets(format!("\"I'm a quote stri><ng\" <{}>", in_brackets)).as_str(), in_brackets);
    let missing_end_quote = format!("\"I'm a quote string <{}>", in_brackets);
    let (r, logs) = testlog::capture(|| get_in_brackets(&missing_end_quote));
    assert_eq!(r.as_str(), missing_end_quote);
    assert_eq!(logs, vec![format!("No closing quote found in '{}'\n", missing_end_quote)]);
    assert_eq!(get_in_brackets(format!("name not in quotes <{}>", in_brackets)).as_str(), in_brackets);
    let no_end_bracket = format!("name not in quotes <{}", in_brackets);
    let (r, logs) = testlog::capture(|| get_in_brackets(&no_end_bracket));
    assert_ne!(r.as_str(), in_brackets);
    assert_eq!(logs, vec![format!("No closing bracket found in '{}'\n", no_end_bracket)]);
    assert_eq!(get_in_brackets("").as_str(), "");
    assert_eq!(get_in_brackets("sip:name@host").as_str(), "sip:name@host");
    assert_eq!(get_in_brackets(format!("{}>", in_brackets)).as_str(), in_brackets);

    let r = get_in_brackets_full("\"x\" <sip:a@b>;tag=1");
    assert_eq!(r, InBrackets { result: 0, out: "sip:a@b".into(), residue: ";tag=1".into() });
    let r = get_in_brackets_full("sip:a@b");
    assert_eq!(r, InBrackets { result: 1, out: "sip:a@b".into(), residue: "".into() });
    let r = get_in_brackets_full("");
    assert_eq!(r, InBrackets { result: 1, out: "".into(), residue: "".into() });
    // An escaped quote inside the quoted part.
    let r = get_in_brackets_full("\"a\\\"<x>\" <sip:a@b>");
    assert_eq!(r.out.as_str(), "sip:a@b");
}

#[test]
fn chan_sip_parse_name_andor_addr() {
    struct Case {
        uri: &'static str,
        name: &'static str,
        user: &'static str,
        pass: &'static str,
        hostport: &'static str,
        residue: &'static str,
        transport: &'static str,
    }
    let cases = [
        Case {
            uri: "\"name :@ \" <sip:user:secret@host:5060;param=discard;transport=tcp>;tag=tag",
            name: "name :@ ",
            user: "user",
            pass: "secret",
            hostport: "host:5060",
            residue: "tag=tag",
            transport: "tcp",
        },
        Case {
            uri: "givenname familyname <sip:user:secret@host:5060;param=discard;transport=tcp>;expires=3600",
            name: "givenname familyname",
            user: "user",
            pass: "secret",
            hostport: "host:5060",
            residue: "expires=3600",
            transport: "tcp",
        },
        Case {
            uri: "sip:user:secret@host:5060;param=discard;transport=tcp;q=1",
            name: "",
            user: "user",
            pass: "secret",
            hostport: "host:5060",
            residue: "q=1",
            transport: "tcp",
        },
        Case { uri: "sips:host", name: "", user: "", pass: "", hostport: "host", residue: "", transport: "" },
    ];
    for c in cases {
        let r = parse_name_andor_addr(c.uri, Some("sip:,sips:"), true, ParseOpts::ALL);
        assert!(!r.uri.error, "{}", c.uri);
        assert_eq!(r.name.as_str(), c.name, "{}", c.uri);
        assert_eq!(r.uri.user.as_str(), c.user, "{}", c.uri);
        assert_eq!(r.uri.pass.as_str(), c.pass, "{}", c.uri);
        assert_eq!(r.uri.hostport.as_str(), c.hostport, "{}", c.uri);
        assert_eq!(r.uri.headers.as_str(), "", "{}", c.uri);
        assert_eq!(r.uri.residue.as_str(), c.residue, "{}", c.uri);
        assert_eq!(r.uri.params.transport.as_str(), c.transport, "{}", c.uri);
    }
}

#[test]
fn to_header_host_and_port() {
    assert_eq!(to_host_port("<sip:000fd3000001@10.0.0.5:5060>"), Some(("10.0.0.5".into(), Some("5060".into()))));
    assert_eq!(to_host_port("\"Phone\" <sip:1001@pbx.example.com>;tag=x"), Some(("pbx.example.com".into(), None)));
    assert_eq!(to_host_port("sip:u@[2001:db8::1]:5061;transport=tls"), Some(("2001:db8::1".into(), Some("5061".into()))));
    assert_eq!(to_host_port("sip:u@host:"), Some(("host".into(), Some("".into()))));
    // The original's scheme list is "sip,sips" without colons, so "sip"
    // also matches "sips:..." and the colon is left on the URI: without a
    // user part the host and port come out wrong.
    assert_eq!(to_host_port("sips:u@host:5061"), Some(("host".into(), Some("5061".into()))));
    assert_eq!(to_host_port("<sip:host:5060>"), Some((":host:5060".into(), None)));
    assert_eq!(to_host_port("sips:[2001:db8::1]:5061"), Some(("s:[2001:db8::1]:5061".into(), None)));
    let (r, logs) = testlog::capture(|| to_host_port("<tel:+15551234>"));
    assert_eq!(r, None);
    assert_eq!(logs, vec!["No supported scheme found in 'tel:+15551234' using the scheme[s] sip,sips\n"]);
    assert_eq!(to_host_port(""), None);
}

#[test]
fn hostport_splitting() {
    assert_eq!(split_hostport("1.2.3.4:5060"), ("1.2.3.4".into(), Some("5060".into())));
    assert_eq!(split_hostport("host"), ("host".into(), None));
    assert_eq!(split_hostport("[::1]:5060"), ("::1".into(), Some("5060".into())));
    assert_eq!(split_hostport("[::1]"), ("::1".into(), None));
    assert_eq!(split_hostport("[::1]x"), ("::1".into(), None));
    assert_eq!(split_hostport("[::1"), ("::1".into(), None));
    assert_eq!(split_hostport("::1"), ("::1".into(), None));
    assert_eq!(split_hostport("a:b:c"), ("a:b:c".into(), None));
}

#[test]
fn uri_decoding() {
    assert_eq!(uri_decode(b"%61lice"), b"alice");
    assert_eq!(uri_decode(b"a%2"), b"a%2");
    assert_eq!(uri_decode(b"a%2b"), b"a+");
    assert_eq!(uri_decode(b"%zz"), b"%zz");
    // sscanf("%2x") quirks: one digit is enough and three characters are
    // consumed anyway; signs and leading blanks are accepted.
    assert_eq!(uri_decode(b"%4g-"), b"\x04-");
    assert_eq!(uri_decode(b"%-1x"), b"\xffx");
    assert_eq!(uri_decode(b"% 41z"), b"A1z");
    assert_eq!(uri_decode(b"+"), b"+");
    // A decoded NUL ends the string.
    assert_eq!(uri_decode(b"ab%00cd"), b"ab");
}

#[test]
fn chan_sip_uri_cmp() {
    let cases: &[(&str, &str, i32)] = &[
        ("sip:bob@example.com", "sip:bob@example.com", 0),
        ("sip:alice@example.com", "sip:bob@example.com", 1),
        ("sip:bob@example.com", "sip:bob@examplez.com", 1),
        ("sip:bob@1.2.3.4", "sip:bob@1.2.3.4", 0),
        ("sip:bob@1.2.3.4", "sip:bob@1.2.3.4:5060", 1),
        ("sip:bob@1.2.3.4:5060", "sip:bob@1.2.3.4:5060", 0),
        ("sip:bob@1.2.3.4:5060", "sip:bob@1.2.3.4:5061", 1),
        ("sip:bob@[2001:db8::1234]", "sip:bob@[2001:db8::1234]", 0),
        ("sip:bob@[2001:db8::1234]", "sip:bob@[2001:db8::1234]:5060", 1),
        ("sip:bob@[2001:db8::1234]:5060", "sip:bob@[2001:db8::1234]:5060", 0),
        ("sip:bob@[2001:db8::1234]:5060", "sip:bob@[2001:db8::1234]:5061", 1),
        ("sips:bob@1.2.3.4", "sip:bob@1.2.3.4", 1),
        ("sip:bob@1.2.3.4;user=phone", "sip:bob@1.2.3.4;user=ip", 1),
        ("sip:bob@1.2.3.4;user=phone", "sip:bob@1.2.3.4;user=phone;transport=udp", 0),
        ("sip:bob@1.2.3.4;user=phone;ttl=7", "sip:bob@1.2.3.4;ttl=7;user=phone", 0),
        ("sip:bob@1.2.3.4;user=phone;ttl=7", "sip:bob@1.2.3.4;user=phone;ttl=8", 1),
        ("sip:bob@1.2.3.4;user=phone", "sip:bob@1.2.3.4;user=phone;maddr=1.2.3.4", 1),
        ("sip:bob@1.2.3.4;user=phone;maddr=1.2.3.4", "sip:bob@1.2.3.4;user=phone", 1),
        ("sip:bob@1.2.3.4;transport=udp", "sip:bob@1.2.3.4;transport=tcp", 1),
        ("sip:bob@1.2.3.4;TRANSPORT=UDP", "sip:bob@1.2.3.4;transport=udp", 0),
        ("sip:bob@1.2.3.4?subject=foo", "sip:bob@1.2.3.4?subject=foo", 0),
        ("sip:bob@1.2.3.4?subject=foo", "sip:bob@1.2.3.4?subject=foo&priority=urgent", 1),
        ("sip:bob@1.2.3.4?subject=foo&priority=urgent", "sip:bob@1.2.3.4?priority=urgent&subject=foo", 0),
        ("sip:bob@1.2.3.4?subject=foo", "sip:bob@1.2.3.4", 1),
        ("sip:bob@1.2.3.4;user=phone?subject=foo", "sip:bob@1.2.3.4;user=phone?subject=FOO", 0),
        ("sip:%61lice@example.com", "sip:alice@example.com", 0),
        ("sip:bob@EXAMPLE.com", "sip:bob@example.com", 0),
        ("sip:BOB@example.com", "sip:bob@example.com", 1),
        ("sip:bob:pw@example.com", "sip:bob:PW@example.com", 1),
        ("sip:example.com", "sip:example.com", 0),
        ("sip:example.com", "sip:bob@example.com", 1),
        ("sip:bob@1.2.3.4", "sip:bob@example.com", 1),
        ("sip:bob@0x01020304", "sip:bob@1.2.3.4", 0),
        ("sip:bob@1.2.772", "sip:bob@1.2.3.4", 0),
        ("sip:bob@[::ffff:1.2.3.4]:5060", "sip:bob@1.2.3.4:5060", 0),
        ("sip:bob@[::ffff:1.2.3.4]", "sip:bob@[::ffff:1.2.3.5]", 1),
        ("tel:123", "tel:123", 1),
        ("sip:", "sip:", 1),
        ("sip", "sip", 1),
    ];
    for &(a, b, expected) in cases {
        assert_eq!(sip_uri_cmp(a, b), expected, "{} vs {}", a, b);
        assert_eq!(sip_uri_cmp(b, a), expected, "{} vs {}", b, a);
    }
}

#[test]
fn phone_utils_uri() {
    assert_eq!(phone_utils_parse_uri("sip:100@1.2.3.4:5060;transport=tcp"), ("1.2.3.4:5060".into(), Some("tcp".into())));
    assert_eq!(phone_utils_parse_uri("pjsip:1.2.3.4:5060;transport=transport-udp;x=y"), ("1.2.3.4:5060".into(), Some("transport-udp".into())));
    assert_eq!(phone_utils_parse_uri("sip:1.2.3.4"), ("1.2.3.4".into(), None));
    assert_eq!(phone_utils_parse_uri("no colon"), ("".into(), None));
    assert_eq!(phone_utils_parse_uri("sip:a@b;transport=udp;transport=tls"), ("b".into(), Some("tls".into())));
    assert_eq!(phone_utils_parse_uri("sip:a;x=1@b"), ("b".into(), None));
    assert_eq!(phone_utils_parse_uri("sip:a@b;transport="), ("b".into(), Some("".into())));

    // In place, as the C export works.
    let mut buf = b"sip:100@host;transport=tls\0junk".to_vec();
    let (addr, transport) = phone_utils_parse_uri_in_place(&mut buf, true);
    assert_eq!((addr, transport), (Some(8), Some(23)));
    assert_eq!(&buf[..26], b"sip\x00100@host\x00transport=tls");
    let mut buf = b"sip:100@host;transport=tls\0".to_vec();
    let (addr, transport) = phone_utils_parse_uri_in_place(&mut buf, false);
    assert_eq!((addr, transport), (Some(8), None));
    let mut buf = b"nothing\0".to_vec();
    assert_eq!(phone_utils_parse_uri_in_place(&mut buf, true), (None, None));
}

#[test]
fn uri_comparison() {
    assert!(same_uri("sip:100@1.2.3.4:5060", "sip:100@1.2.3.4:5060;transport=udp"));
    assert!(same_uri("sip:100@HOST:5060;transport=TCP", "sip:200@host:5060;transport=tcp"));
    assert!(!same_uri("sip:100@1.2.3.4:5060;transport=tcp", "sip:100@1.2.3.4:5060"));
    assert!(!same_uri("sip:100@1.2.3.4:5060", "sip:100@1.2.3.4:5061"));
    assert!(same_uri("x", "y"));
}
