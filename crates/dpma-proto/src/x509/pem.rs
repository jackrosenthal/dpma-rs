//! The PEM reader of OpenSSL 1.1.1t (`crypto/pem/pem_lib.c`,
//! `PEM_read_bio_ex` with `PEM_FLAG_EAY_COMPATIBLE`, and the base64
//! decoder `EVP_DecodeUpdate` in `crypto/evp/encode.c`), on a memory BIO.
//!
//! What it tolerates, as 1.1.1t does:
//!
//! - Any text before, between, and after the PEM blocks: lines that are not
//!   a `-----BEGIN <label>-----` line are skipped while looking for one.
//! - Blocks with other labels than the one wanted are read and skipped
//!   (they must still be well formed); `X509 CERTIFICATE` is read as
//!   `CERTIFICATE`.
//! - Trailing white space, control characters, and octets 0x80 and above
//!   at the end of each line (1.1.1t strips octets up to space as a signed
//!   `char`), so CRLF line ends.
//! - Lines of any length (read 254 octets at a time) and white space inside
//!   the base64 text; a `-` ends the base64 text early.
//! - RFC 1421 headers (`Proc-Type`, `DEK-Info`) followed by a blank line.
//!
//! What it rejects: an END line that does not match the BEGIN line exactly,
//! a missing END line, base64 errors (other characters, data after `=`
//! padding, a length that is not a multiple of four), a blank line inside
//! the base64 text (it is taken as the end of a header that is not one),
//! and an empty block.  An encrypted block (`Proc-Type: 4,ENCRYPTED`)
//! makes 1.1.1t ask for a pass phrase on the terminal (or standard input)
//! of the process; here the read fails as it does in 1.1.1t when no pass
//! phrase can be read.  Only `DES-CBC`, `DES-EDE3-CBC`, and the AES CBC
//! ciphers (and their aliases) are known as DEK-Info algorithms; 1.1.1t
//! also knows others, for which it would report a different error.

use super::Certificate;
use crate::errstack::{self, pem as e, Errs, LIB_PEM, R_ASN1_LIB};

const PEM_LIB: &str = "crypto/pem/pem_lib.c";

/// A memory BIO.
pub(crate) struct Bio<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Bio<'a> {
    pub fn new(data: &'a [u8]) -> Bio<'a> {
        Bio { data, pos: 0 }
    }

    /// `BIO_gets(bio, buf, size)` (`mem_gets`): up to `size - 1` octets,
    /// through the first newline.
    fn gets(&mut self, size: usize) -> &'a [u8] {
        let rest = &self.data[self.pos..];
        let j = rest.len().min(size - 1);
        let n = rest[..j].iter().position(|&c| c == b'\n').map(|i| i + 1).unwrap_or(j);
        self.pos += n;
        &rest[..n]
    }
}

const LINESIZE: usize = 255;
const BEGIN: &[u8] = b"-----BEGIN ";
const END: &[u8] = b"-----END ";
const TAIL: &[u8] = b"-----\n";

/// `sanitize_line` with `PEM_FLAG_EAY_COMPATIBLE`: strip the trailing
/// octets that are `<= ' '` as a signed char and end the line with `\n`.
fn sanitize(line: &[u8]) -> Vec<u8> {
    let mut n = line.len();
    while n > 0 && (line[n - 1] <= b' ' || line[n - 1] >= 0x80) {
        n -= 1;
    }
    let mut out = line[..n].to_vec();
    out.push(b'\n');
    out
}

/// The part of `s` before its first NUL (how 1.1.1t's C strings see it).
fn c_str(s: &[u8]) -> &[u8] {
    &s[..s.iter().position(|&c| c == 0).unwrap_or(s.len())]
}

/// A block read by `PEM_read_bio_ex`.
struct Block {
    name: Vec<u8>,
    header: Vec<u8>,
    data: Vec<u8>,
}

/// `get_name`: skip to a BEGIN line and return its label.
fn get_name(bio: &mut Bio, errs: &mut Errs) -> Option<Vec<u8>> {
    loop {
        let raw = bio.gets(LINESIZE);
        if raw.is_empty() {
            errs.put(LIB_PEM, e::F_GET_NAME, e::R_NO_START_LINE, PEM_LIB, 745);
            return None;
        }
        let line = sanitize(raw);
        if line.starts_with(BEGIN) && line.len() >= TAIL.len() && line.ends_with(TAIL) {
            return Some(c_str(&line[BEGIN.len()..line.len() - TAIL.len()]).to_vec());
        }
    }
}

/// `get_header_and_data`.  None with or without a recorded error, as in
/// 1.1.1t.
fn get_header_and_data(bio: &mut Bio, name: &[u8], errs: &mut Errs) -> Option<(Vec<u8>, Vec<u8>)> {
    #[derive(PartialEq)]
    enum Hdr {
        Maybe,
        In,
        Post,
    }
    let mut header = Vec::new();
    let mut data = Vec::new();
    let mut to_data = false;
    let mut got_header = Hdr::Maybe;
    let mut partial = false;
    let mut end = false;
    loop {
        let raw = bio.gets(LINESIZE);
        if raw.is_empty() {
            errs.put(LIB_PEM, e::F_GET_HEADER_AND_DATA, e::R_BAD_END_LINE, PEM_LIB, 812);
            return None;
        }
        let prev_partial = partial;
        partial = raw.len() == LINESIZE - 1 && raw[LINESIZE - 2] != b'\n';
        if got_header == Hdr::Maybe && raw.contains(&b':') {
            got_header = Hdr::In;
        }
        let line = sanitize(raw);
        if line[0] == b'\n' {
            if !prev_partial {
                if got_header == Hdr::Post {
                    errs.put(LIB_PEM, e::F_GET_HEADER_AND_DATA, e::R_BAD_END_LINE, PEM_LIB, 841);
                    return None;
                }
                got_header = Hdr::Post;
                to_data = true;
            }
            continue;
        }
        if line.starts_with(END) {
            // The END line must be "-----END <name>-----" (the line ends
            // right after the dashes: sanitize added the only newline).
            let p = &line[END.len()..];
            if !(p.starts_with(name) && p[name.len()..].starts_with(TAIL)) {
                errs.put(LIB_PEM, e::F_GET_HEADER_AND_DATA, e::R_BAD_END_LINE, PEM_LIB, 856);
                return None;
            }
            if got_header == Hdr::Maybe {
                // No header after all: what was read is the data.
                return Some((data, header));
            }
            return Some((header, data));
        } else if end {
            errs.put(LIB_PEM, e::F_GET_HEADER_AND_DATA, e::R_BAD_END_LINE, PEM_LIB, 866);
            return None;
        }
        // BIO_puts writes the line as a C string.
        let text = c_str(&line);
        if to_data {
            data.extend_from_slice(text);
        } else {
            header.extend_from_slice(text);
        }
        if got_header == Hdr::Post {
            // After a header, lines must be 64 characters (the last
            // shorter).  1.1.1t records no error for a longer one.
            if line.len() > 65 {
                return None;
            }
            if line.len() < 65 {
                end = true;
            }
        }
    }
}

/// `PEM_read_bio_ex`.
fn read_bio_ex(bio: &mut Bio, errs: &mut Errs) -> Option<Block> {
    let name = get_name(bio, errs)?;
    let (header, data) = get_header_and_data(bio, &name, errs)?;
    if data.is_empty() {
        // "There was no data in the PEM file": no error recorded.
        return None;
    }
    match base64_decode(&data) {
        Some(data) => Some(Block { name, header: c_str(&header).to_vec(), data }),
        None => {
            errs.put(LIB_PEM, e::F_PEM_READ_BIO_EX, e::R_BAD_BASE64_DECODE, PEM_LIB, 949);
            None
        }
    }
}

/// `EVP_DecodeUpdate` over the whole text, then `EVP_DecodeFinal`; None
/// where either fails.
fn base64_decode(input: &[u8]) -> Option<Vec<u8>> {
    // data_ascii2bin: 0xE0 white space, 0xF0 newline, 0xF1 carriage return,
    // 0xF2 end ('-'), 0xFF error.
    fn conv(c: u8) -> u8 {
        match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => 0,
            b'\t' | b' ' => 0xe0,
            b'\n' => 0xf0,
            b'\r' => 0xf1,
            b'-' => 0xf2,
            _ => 0xff,
        }
    }
    let not_base64 = |v: u8| (v | 0x13) == 0xf3;
    // evp_decodeblock_int on a buffer of base64 characters.
    fn block(f: &[u8], out: &mut Vec<u8>) -> Option<usize> {
        let mut f = f;
        while let Some((&c, rest)) = f.split_first() {
            if conv(c) != 0xe0 {
                break;
            }
            f = rest;
        }
        let mut n = f.len();
        while n > 3 && (conv(f[n - 1]) | 0x13) == 0xf3 {
            n -= 1;
        }
        if !n.is_multiple_of(4) {
            return None;
        }
        for q in f[..n].chunks(4) {
            let v: Vec<u8> = q.iter().map(|&c| conv(c)).collect();
            if v.iter().any(|&x| x & 0x80 != 0) {
                return None;
            }
            let l = (u32::from(v[0]) << 18) | (u32::from(v[1]) << 12) | (u32::from(v[2]) << 6) | u32::from(v[3]);
            out.extend([(l >> 16) as u8, (l >> 8) as u8, l as u8]);
        }
        Some(n / 4 * 3)
    }
    let mut out = Vec::new();
    let mut d: Vec<u8> = Vec::with_capacity(64);
    let mut eof = 0usize;
    let mut seof = false;
    for &c in input {
        let v = conv(c);
        if v == 0xff {
            return None;
        }
        if c == b'=' {
            eof += 1;
        } else if eof > 0 && !not_base64(v) {
            return None;
        }
        if eof > 2 {
            return None;
        }
        if v == 0xf2 {
            seof = true;
            break;
        }
        if !not_base64(v) {
            d.push(c);
        }
        if d.len() == 64 {
            let mut tmp = Vec::new();
            let len = block(&d, &mut tmp)?;
            d.clear();
            if eof > len {
                return None;
            }
            out.extend_from_slice(&tmp[..len - eof]);
        }
    }
    if !d.is_empty() {
        if d.len().is_multiple_of(4) {
            let mut tmp = Vec::new();
            let len = block(&d, &mut tmp)?;
            d.clear();
            if eof > len {
                return None;
            }
            out.extend_from_slice(&tmp[..len - eof]);
        } else if seof {
            return None;
        }
    }
    // EVP_DecodeFinal: what is left must be a whole block (and its padding
    // is not subtracted).
    if !d.is_empty() {
        let mut tmp = Vec::new();
        block(&d, &mut tmp)?;
        out.extend(tmp);
    }
    Some(out)
}

/// `check_pem(nm, name)` for the two labels read here.
fn check_pem(nm: &[u8], name: &[u8]) -> bool {
    nm == name || (name == b"CERTIFICATE" && nm == b"X509 CERTIFICATE")
}

/// `pem_bytes_read_bio_flags`: the next block labeled `name` (skipping
/// others), its header processed.
fn bytes_read_bio(bio: &mut Bio, name: &[u8], errs: &mut Errs) -> Option<Vec<u8>> {
    let block = loop {
        let b = read_bio_ex(bio, errs)?;
        if check_pem(&b.name, name) {
            break b;
        }
    };
    let cipher = cipher_info(&block.header, errs)?;
    if cipher.is_some() {
        // PEM_do_header calls PEM_def_callback, which asks for a pass
        // phrase; with no terminal and nothing on standard input,
        // UI_process fails.
        errs.put(errstack::LIB_UI, errstack::ui::F_UI_PROCESS, errstack::ui::R_PROCESSING_ERROR, "crypto/ui/ui_lib.c", 545);
        errs.put(LIB_PEM, e::F_PEM_DEF_CALLBACK, e::R_PROBLEMS_GETTING_PASSWORD, PEM_LIB, 59);
        errs.put(LIB_PEM, e::F_PEM_DO_HEADER, e::R_BAD_PASSWORD_READ, PEM_LIB, 434);
        return None;
    }
    Some(block.data)
}

/// `PEM_get_EVP_CIPHER_INFO`: Ok(None) for no encryption, Ok(Some(iv
/// length)) for a known cipher, None for an error.
fn cipher_info(header: &[u8], errs: &mut Errs) -> Option<Option<usize>> {
    let fail = |errs: &mut Errs, r: u32, line: u32| {
        errs.put(LIB_PEM, e::F_PEM_GET_EVP_CIPHER_INFO, r, PEM_LIB, line);
        None
    };
    let at = |h: &[u8], i: usize| h.get(i).copied().unwrap_or(0);
    let spn = |h: &[u8], i: usize, set: &[u8]| {
        let mut i = i;
        while i < h.len() && set.contains(&h[i]) {
            i += 1;
        }
        i
    };
    if header.is_empty() || header[0] == b'\n' {
        return Some(None);
    }
    if !header.starts_with(b"Proc-Type:") {
        return fail(errs, e::R_NOT_PROC_TYPE, 496);
    }
    let mut i = spn(header, 10, b" \t");
    if at(header, i) != b'4' {
        return None;
    }
    i += 1;
    if at(header, i) != b',' {
        return None;
    }
    i = spn(header, i + 1, b" \t");
    if !header[i..].starts_with(b"ENCRYPTED") || spn(header, i + 9, b" \t\r\n") == i + 9 {
        return fail(errs, e::R_NOT_ENCRYPTED, 509);
    }
    i = spn(header, i + 9, b" \t\r");
    if at(header, i) != b'\n' {
        return fail(errs, e::R_SHORT_HEADER, 515);
    }
    i += 1;
    if !header[i..].starts_with(b"DEK-Info:") {
        return fail(errs, e::R_NOT_DEK_INFO, 524);
    }
    i = spn(header, i + 9, b" \t");
    let start = i;
    while i < header.len() && !b" \t,".contains(&header[i]) {
        i += 1;
    }
    let alg = &header[start..i];
    i = spn(header, i, b" \t");
    let Some(ivlen) = cipher_iv_len(alg) else {
        return fail(errs, e::R_UNSUPPORTED_ENCRYPTION, 543);
    };
    if ivlen > 0 {
        if at(header, i) != b',' {
            return fail(errs, e::R_MISSING_DEK_IV, 548);
        }
        i += 1;
    } else if at(header, i) == b',' {
        return fail(errs, e::R_UNEXPECTED_DEK_IV, 551);
    }
    for k in 0..ivlen * 2 {
        if !at(header, i + k).is_ascii_hexdigit() {
            errs.put(LIB_PEM, e::F_LOAD_IV, e::R_BAD_IV_CHARS, PEM_LIB, 573);
            return None;
        }
    }
    Some(Some(ivlen))
}

/// `EVP_get_cipherbyname` for the usual DEK-Info ciphers: their IV length.
fn cipher_iv_len(name: &[u8]) -> Option<usize> {
    const NAMES: &[(&[u8], usize)] = &[
        (b"AES-128-CBC", 16),
        (b"AES-192-CBC", 16),
        (b"AES-256-CBC", 16),
        (b"aes-128-cbc", 16),
        (b"aes-192-cbc", 16),
        (b"aes-256-cbc", 16),
        (b"AES128", 16),
        (b"AES192", 16),
        (b"AES256", 16),
        (b"aes128", 16),
        (b"aes192", 16),
        (b"aes256", 16),
        (b"DES-CBC", 8),
        (b"des-cbc", 8),
        (b"DES", 8),
        (b"des", 8),
        (b"DES-EDE3-CBC", 8),
        (b"des-ede3-cbc", 8),
        (b"DES3", 8),
        (b"des3", 8),
    ];
    NAMES.iter().find(|(n, _)| *n == name).map(|(_, l)| *l)
}

/// `PEM_read_bio_X509`: the next certificate, or None with 1.1.1t's errors
/// recorded.
pub(crate) fn read_bio_x509(bio: &mut Bio, errs: &mut Errs) -> Option<Certificate> {
    let data = bytes_read_bio(bio, b"CERTIFICATE", errs)?;
    match Certificate::d2i(&data, errs) {
        Some(c) => Some(c),
        None => {
            errs.put(LIB_PEM, e::F_PEM_ASN1_READ_BIO, R_ASN1_LIB, "crypto/pem/pem_oth.c", 33);
            None
        }
    }
}

/// `PEM_read_bio_PUBKEY`'s first half: the DER of the next `PUBLIC KEY`
/// block.
pub(crate) fn read_bio_pubkey_der(bio: &mut Bio, errs: &mut Errs) -> Option<Vec<u8>> {
    bytes_read_bio(bio, b"PUBLIC KEY", errs)
}

/// PEM text of DER data (64 characters a line), as `PEM_write` writes it.
pub(crate) fn encode(label: &str, der: &[u8]) -> String {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = format!("-----BEGIN {}-----\n", label);
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        out.push('\n');
    }
    out.push_str(&format!("-----END {}-----\n", label));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errstack::error_string;

    /// Each block's label and data.
    type Blocks = Vec<(Vec<u8>, Vec<u8>)>;

    fn blocks(text: &[u8]) -> (Blocks, Errs) {
        let mut bio = Bio::new(text);
        let mut errs = Errs::new();
        let mut out = Vec::new();
        while let Some(b) = read_bio_ex(&mut bio, &mut errs) {
            out.push((b.name, b.data));
        }
        (out, errs)
    }

    #[test]
    fn base64_rules() {
        assert_eq!(base64_decode(b"QUJD\n").unwrap(), b"ABC");
        assert_eq!(base64_decode(b"QUI=\n").unwrap(), b"AB");
        assert_eq!(base64_decode(b"QQ==\n").unwrap(), b"A");
        assert_eq!(base64_decode(b" Q U J D \n").unwrap(), b"ABC");
        // '-' ends the text.
        assert_eq!(base64_decode(b"QUJD\n-----x").unwrap(), b"ABC");
        assert!(base64_decode(b"QUJ\n-").is_none());
        assert!(base64_decode(b"QUI=QQ==\n").is_none());
        assert!(base64_decode(b"QUJ\n").is_none());
        assert!(base64_decode(b"QU*D\n").is_none());
        assert!(base64_decode(b"Q===\n").is_none());
        let long: Vec<u8> = b"QUJD".iter().cycle().take(64 * 3).copied().chain(*b"\n").collect();
        assert_eq!(base64_decode(&long).unwrap().len(), 144);
    }

    #[test]
    fn framing() {
        let (b, errs) = blocks(b"junk\n-----BEGIN A-----\nQUJD\n-----END A-----\nmore\n-----BEGIN B-----\r\nQUJD  \r\n-----END B-----   \r\n");
        assert_eq!(b, vec![(b"A".to_vec(), b"ABC".to_vec()), (b"B".to_vec(), b"ABC".to_vec())]);
        assert_eq!(error_string(errs.peek()), "error:0909006C:PEM routines:get_name:no start line");
        // A mismatched END line, a missing one, extra text after it.
        for bad in [
            &b"-----BEGIN A-----\nQUJD\n-----END B-----\n"[..],
            b"-----BEGIN A-----\nQUJD\n",
            b"-----BEGIN A-----\nQUJD\n-----END A-----x\n",
        ] {
            let (b, errs) = blocks(bad);
            assert!(b.is_empty());
            assert_eq!(error_string(errs.peek()), "error:0908F066:PEM routines:get_header_and_data:bad end line");
        }
        // An empty block fails without an error.
        let (b, errs) = blocks(b"-----BEGIN A-----\n-----END A-----\n");
        assert!(b.is_empty() && errs.0.is_empty());
        // Bad base64.
        let (_, errs) = blocks(b"-----BEGIN A-----\nQU!D\n-----END A-----\n");
        assert_eq!(error_string(errs.peek()), "error:09091064:PEM routines:PEM_read_bio_ex:bad base64 decode");
        // A blank line inside the data makes the first part a "header".
        let mut bio = Bio::new(b"-----BEGIN CERTIFICATE-----\nQUJD\n\nQUJD\n-----END CERTIFICATE-----\n");
        let mut errs = Errs::new();
        assert!(bytes_read_bio(&mut bio, b"CERTIFICATE", &mut errs).is_none());
        assert_eq!(error_string(errs.peek()), "error:0906B06B:PEM routines:PEM_get_EVP_CIPHER_INFO:not proc type");
        // A blank line before the data is fine.
        let mut bio = Bio::new(b"-----BEGIN CERTIFICATE-----\n\nQUJD\n-----END CERTIFICATE-----\n");
        assert_eq!(bytes_read_bio(&mut bio, b"CERTIFICATE", &mut Errs::new()).unwrap(), b"ABC");
        // Long lines are read in pieces.
        let long = format!("-----BEGIN A-----\n{}\n-----END A-----\n", "QUJD".repeat(100));
        assert_eq!(blocks(long.as_bytes()).0[0].1.len(), 300);
    }

    #[test]
    fn encrypted_blocks() {
        let text = b"-----BEGIN CERTIFICATE-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00112233445566778899AABBCCDDEEFF\n\nQUJD\n-----END CERTIFICATE-----\n";
        let mut errs = Errs::new();
        assert!(bytes_read_bio(&mut Bio::new(text), b"CERTIFICATE", &mut errs).is_none());
        assert_eq!(error_string(errs.peek()), "error:2807106B:UI routines:UI_process:processing error");
        let text = b"-----BEGIN CERTIFICATE-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: CAMELLIA-128-XYZ,00\n\nQUJD\n-----END CERTIFICATE-----\n";
        let mut errs = Errs::new();
        assert!(bytes_read_bio(&mut Bio::new(text), b"CERTIFICATE", &mut errs).is_none());
        assert_eq!(error_string(errs.peek()), "error:0906B072:PEM routines:PEM_get_EVP_CIPHER_INFO:unsupported encryption");
    }
}
