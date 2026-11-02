//! A small client for the Asterisk REST Interface (ARI) over HTTP.
//!
//! The instance must have HTTP enabled (`http.conf`) and an ARI user
//! (`ari.conf`); the scratch configuration has neither, so a suite that
//! needs ARI installs both (see the pjsip-helpers suite).  Every HTTP
//! status comes back as a status (4xx and 5xx are not errors); only
//! transport failures are.
//!
//! ```no_run
//! use dpma_tests::ari::Ari;
//! # fn main() -> anyhow::Result<()> {
//! let ari = Ari::new("127.0.0.1", 17688, "user", "secret");
//! // Push configuration (sorcery memory wizards): create or update an
//! // object, then delete it.
//! let status = ari.put_dynamic_config("res_pjsip", "endpoint", "2005", &[("context", "phones")])?;
//! assert_eq!(status, 200);
//! assert_eq!(ari.delete_dynamic_config("res_pjsip", "endpoint", "2005")?, 204);
//! let r = ari.request("GET", "asterisk/info", None)?;
//! println!("{} {}", r.status, String::from_utf8_lossy(&r.body));
//! # Ok(()) }
//! ```

use std::time::Duration;

use anyhow::{Context, Result};
use base64::Engine;
use serde_json::{json, Value};
use ureq::http;

/// An HTTP response from ARI.
#[derive(Clone, Debug)]
pub struct AriResponse {
    /// The HTTP status code.
    pub status: u16,
    /// The body.
    pub body: Vec<u8>,
}

impl AriResponse {
    /// The body as JSON (`Null` when it is not JSON).
    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }
}

/// An ARI client for one Asterisk HTTP server and ARI user.
#[derive(Clone)]
pub struct Ari {
    base: String,
    authorization: String,
    agent: ureq::Agent,
}

impl Ari {
    /// A client for `http://<host>:<port>/ari/`, authenticating as
    /// `user` (HTTP basic authentication), with a 10-second timeout.
    pub fn new(host: &str, port: u16, user: &str, password: &str) -> Ari {
        Ari::with_timeout(host, port, user, password, Duration::from_secs(10))
    }

    /// [`Ari::new`] with another timeout for each request (connecting,
    /// sending, and reading the response).
    ///
    /// Every request uses a new connection.
    pub fn with_timeout(
        host: &str,
        port: u16,
        user: &str,
        password: &str,
        timeout: Duration,
    ) -> Ari {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .timeout_global(Some(timeout))
            .max_idle_connections(0)
            .max_idle_connections_per_host(0)
            .build()
            .into();
        let credentials =
            base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"));
        Ari {
            base: format!("http://{host}:{port}/ari/"),
            authorization: format!("Basic {credentials}"),
            agent,
        }
    }

    /// The URL of `path` (relative to `/ari/`).
    pub fn url(&self, path: &str) -> String {
        format!("{}{}", self.base, path.trim_start_matches('/'))
    }

    /// Sends `method` to `path` (relative to `/ari/`, e.g.,
    /// `asterisk/info`) with an optional JSON body.
    pub fn request(&self, method: &str, path: &str, body: Option<&Value>) -> Result<AriResponse> {
        let url = self.url(path);
        let builder = http::Request::builder()
            .method(method)
            .uri(&url)
            .header("Authorization", &self.authorization);
        let resp = match body {
            Some(v) => {
                let req = builder
                    .header("Content-Type", "application/json")
                    .body(serde_json::to_vec(v)?)?;
                self.agent.run(req)
            }
            None => self.agent.run(builder.body(())?),
        };
        let mut resp = resp.with_context(|| format!("ARI {method} {url}"))?;
        let status = resp.status().as_u16();
        let body = resp.body_mut().read_to_vec().unwrap_or_default();
        Ok(AriResponse { status, body })
    }

    /// The body of a push configuration request (`PUT
    /// /asterisk/config/dynamic/...`): `{"fields": [{"attribute": NAME,
    /// "value": VALUE}, ...]}`.
    pub fn config_fields(fields: &[(&str, &str)]) -> Value {
        json!({"fields": fields
            .iter()
            .map(|(k, v)| json!({"attribute": k, "value": v}))
            .collect::<Vec<_>>()})
    }

    /// Creates or updates a sorcery object through push configuration
    /// (`PUT /asterisk/config/dynamic/<class>/<type>/<id>`); the HTTP
    /// status.  Without fields, no body is sent.  The object type needs a
    /// writable wizard (e.g., `memory` in `sorcery.conf`).
    pub fn put_dynamic_config(
        &self,
        config_class: &str,
        object_type: &str,
        id: &str,
        fields: &[(&str, &str)],
    ) -> Result<u16> {
        let path = format!("asterisk/config/dynamic/{config_class}/{object_type}/{id}");
        let body = (!fields.is_empty()).then(|| Ari::config_fields(fields));
        Ok(self.request("PUT", &path, body.as_ref())?.status)
    }

    /// Deletes a sorcery object through push configuration (`DELETE
    /// /asterisk/config/dynamic/<class>/<type>/<id>`); the HTTP status.
    pub fn delete_dynamic_config(
        &self,
        config_class: &str,
        object_type: &str,
        id: &str,
    ) -> Result<u16> {
        let path = format!("asterisk/config/dynamic/{config_class}/{object_type}/{id}");
        Ok(self.request("DELETE", &path, None)?.status)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;

    /// A one-request HTTP server: returns the request it got.
    fn serve_once(listener: TcpListener, status: &'static str) -> std::thread::JoinHandle<String> {
        std::thread::spawn(move || {
            let (s, _) = listener.accept().unwrap();
            let mut r = BufReader::new(s.try_clone().unwrap());
            let mut head = String::new();
            let mut len = 0;
            loop {
                let mut line = String::new();
                r.read_line(&mut line).unwrap();
                if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    len = v.trim().parse().unwrap();
                }
                head.push_str(&line);
                if line == "\r\n" {
                    break;
                }
            }
            let mut body = vec![0; len];
            r.read_exact(&mut body).unwrap();
            let mut s = s;
            write!(
                s,
                "HTTP/1.1 {status}\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}"
            )
            .unwrap();
            head + &String::from_utf8_lossy(&body)
        })
    }

    #[test]
    fn put_and_delete() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let h = serve_once(l, "200 OK");
        let ari = Ari::new("127.0.0.1", port, "u", "p");
        let status = ari
            .put_dynamic_config(
                "res_pjsip",
                "auth",
                "a-1",
                &[("username", "x"), ("password", "")],
            )
            .unwrap();
        assert_eq!(status, 200);
        let req = h.join().unwrap();
        assert!(
            req.starts_with("PUT /ari/asterisk/config/dynamic/res_pjsip/auth/a-1 HTTP/1.1\r\n"),
            "{req}"
        );
        assert!(
            req.contains("Authorization: Basic dTpw\r\n")
                || req.contains("authorization: Basic dTpw\r\n"),
            "{req}"
        );
        assert!(req.ends_with(
            r#"{"fields":[{"attribute":"username","value":"x"},{"attribute":"password","value":""}]}"#
        ));

        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let h = serve_once(l, "404 Not Found");
        let ari = Ari::new("127.0.0.1", port, "u", "p");
        assert_eq!(
            ari.delete_dynamic_config("res_pjsip", "aor", "x").unwrap(),
            404
        );
        let req = h.join().unwrap();
        assert!(
            req.starts_with("DELETE /ari/asterisk/config/dynamic/res_pjsip/aor/x HTTP/1.1\r\n"),
            "{req}"
        );
    }
}
