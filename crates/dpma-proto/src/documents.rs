//! The documents that phones send in requests.

/// The body of a FileRequest for `name` (`default`, `null`, or a file).
pub fn file_request(name: impl AsRef<[u8]>) -> Vec<u8> {
    [b"file://", name.as_ref()].concat()
}

/// The credentials line of an AsteriskRequest or HTTPRequest body:
/// `X-Digium-AppServer-Digest-Auth=USER:SECRET` and a line break.
pub fn digest_auth_line(credentials: impl AsRef<[u8]>) -> Vec<u8> {
    let mut v = crate::headers::DIGEST_AUTH_MARKER.as_bytes().to_vec();
    v.extend_from_slice(credentials.as_ref());
    v.extend_from_slice(b"\r\n");
    v
}

/// `document` with the credentials line in front.
pub fn with_digest_auth(credentials: impl AsRef<[u8]>, document: impl AsRef<[u8]>) -> Vec<u8> {
    let mut v = digest_auth_line(credentials);
    v.extend_from_slice(document.as_ref());
    v
}

/// A JSON method call document: `{"request": {"method": M, "parameters":
/// P}}` (no parameters when `params` is `None`).
pub fn method_call_json(method: &str, params: Option<&serde_json::Value>) -> String {
    let mut request = serde_json::Map::new();
    request.insert("method".into(), method.into());
    if let Some(params) = params {
        request.insert("parameters".into(), params.clone());
    }
    let mut document = serde_json::Map::new();
    document.insert("request".into(), request.into());
    serde_json::Value::Object(document).to_string()
}

/// An XML method call document; `params` is an XML fragment.
pub fn method_call_xml(method: &str, params: &str) -> String {
    format!("<request method=\"{method}\"><parameters>{params}</parameters></request>")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn method_calls() {
        assert_eq!(
            method_call_json("m", Some(&serde_json::json!({"x": [1]}))),
            r#"{"request":{"method":"m","parameters":{"x":[1]}}}"#
        );
        assert_eq!(method_call_json("m", None), r#"{"request":{"method":"m"}}"#);
        assert_eq!(
            method_call_xml("m", "<x/>"),
            r#"<request method="m"><parameters><x/></parameters></request>"#
        );
        assert_eq!(
            with_digest_auth("u:s", "doc"),
            b"X-Digium-AppServer-Digest-Auth=u:s\r\ndoc"
        );
    }
}
