# dpma-proto

The protocol that Digium phones speak to their application server (the
Digium Phone Module for Asterisk, DPMA), as a Rust library with no Asterisk
dependency.

It is the protocol half of [dpma-rs](https://github.com/jackrosenthal/dpma-rs),
an open source replacement for the official DPMA.  The code follows the
official module's behavior closely, including its error texts and limits, so
that what it produces and accepts is what phones expect.  It is written from
the server's side; the pieces that do not depend on direction (encryption,
framing, and URI parsing) can also serve a phone-side client.

## What is in it

- `crypto`: message encryption (AES-128-CBC with a key and IV derived from a
  shared "common password" and a per-message salt), and the encryption of
  that password to a phone's public key.
- `message`: whole exchanges as plain data (a `Message` is one SIP MESSAGE):
  encoding what a server or a phone sends, and decoding what arrives.
- `framing`: the chunking and the transaction keys underneath `message`.
- `cert`: decoding a phone's certificates and verifying them against a CA
  store.
- `uri`: SIP URI and header parsing, and URI comparison.
- `headers`, `types`, and `errors`: the `X-Digium-AppServer-*` header names,
  request and response types, and error codes with their texts.
- `xml` and `json`: escaping and serialization that match what Asterisk
  produces.

## How a session works

Phones and the server exchange SIP MESSAGEs whose headers are the
`X-Digium-AppServer-*` variables in `headers`.

1. The phone sends a `Handshake` request whose body is its certificates.  The
   server verifies them, makes a random common password for the session, and
   answers with a `HandshakeResponse` carrying the password, RSA-encrypted to
   the phone's key.
2. Every later message, in both directions, is encrypted with that password
   and a fresh salt, and split across as many MESSAGEs as needed.
3. A request has a request type, and its answer has the matching response type
   (`types::response_type_for`).

The `message` module does the encryption, the chunking, and the headers for
both sides, on `Message` values that you carry to and from your SIP stack.

## Examples

Two runnable examples use `message` over a real SIP stack,
[`rsipstack`](https://crates.io/crates/rsipstack), which is where the SIP
lives (`examples/common/mod.rs`); everything about the protocol is the
crate's.

- [`examples/server.rs`](https://github.com/jackrosenthal/dpma-rs/blob/main/crates/dpma-proto/examples/server.rs)
  is a server.  It verifies a phone's certificates, answers the Handshake with
  the session's password, and answers requests.  It trusts the CA certificates
  built into the official DPMA unless you pass others.
- [`examples/phone.rs`](https://github.com/jackrosenthal/dpma-rs/blob/main/crates/dpma-proto/examples/phone.rs)
  is a phone.  It handshakes with the certificates and key you give it, then
  sends a PingRequest and reads the reply.

```text
cargo run --example server -- 127.0.0.1:5060 [CA_CERTIFICATES.pem]
cargo run --example phone -- 127.0.0.1:5060 CERTIFICATES.pem PRIVATE_KEY.pem
```
