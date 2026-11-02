//! The error codes and texts of OpenSSL 1.1.1t, which the original module
//! links statically.
//!
//! Where the original logs an OpenSSL error, it formats an error code from
//! 1.1.1t's per-thread error queue: `ERR_error_string_n` ("Unable to read
//! client cert: %s") or `ERR_print_errors` (`log_ssl`).  The functions
//! ported here that can fail that way record the errors 1.1.1t would push,
//! with its library, function, and reason codes and its source file and
//! line, in an error list, and the callers format them the same way.
//!
//! One difference: 1.1.1t's queue is per thread and the original never
//! clears it, so its messages can name an error left over from an earlier
//! operation on the same thread (for example, the "no start line" that
//! every handshake leaves behind when it reads past the last certificate).
//! Here each operation starts with an empty list, so a message names the
//! errors of the failure it reports.

/// `ERR_LIB_BN`.
pub(crate) const LIB_BN: u32 = 3;
/// `ERR_LIB_RSA`.
pub(crate) const LIB_RSA: u32 = 4;
/// `ERR_LIB_EVP`.
pub(crate) const LIB_EVP: u32 = 6;
/// `ERR_LIB_PEM`.
pub(crate) const LIB_PEM: u32 = 9;
/// `ERR_LIB_ASN1`.
pub(crate) const LIB_ASN1: u32 = 13;
/// `ERR_LIB_RAND`.
pub(crate) const LIB_RAND: u32 = 36;
/// `ERR_LIB_UI`.
pub(crate) const LIB_UI: u32 = 40;

/// `ERR_R_NESTED_ASN1_ERROR`.
pub(crate) const R_NESTED_ASN1_ERROR: u32 = 58;
/// `ERR_R_ASN1_LIB`.
pub(crate) const R_ASN1_LIB: u32 = 13;

/// `ERR_PACK(lib, func, reason)`.
pub(crate) const fn pack(lib: u32, func: u32, reason: u32) -> u32 {
    ((lib & 0xff) << 24) | ((func & 0xfff) << 12) | (reason & 0xfff)
}

/// One queued error: its packed code and where 1.1.1t raises it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Err {
    pub code: u32,
    pub file: &'static str,
    pub line: u32,
}

/// The errors one operation pushed, oldest first.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct Errs(pub Vec<Err>);

impl Errs {
    pub fn new() -> Errs {
        Errs::default()
    }

    /// `ERR_put_error`.
    pub fn put(&mut self, lib: u32, func: u32, reason: u32, file: &'static str, line: u32) {
        self.0.push(Err { code: pack(lib, func, reason), file, line });
    }

    /// `ERR_get_error`: the oldest error (0 when there is none), removed.
    pub fn get(&mut self) -> u32 {
        if self.0.is_empty() {
            0
        } else {
            self.0.remove(0).code
        }
    }

    /// `ERR_peek_error`: the oldest error's code (0 when there is none).
    pub fn peek(&self) -> u32 {
        self.0.first().map(|e| e.code).unwrap_or(0)
    }

    /// The newest error's code (0 when there is none).
    pub fn last(&self) -> u32 {
        self.0.last().map(|e| e.code).unwrap_or(0)
    }

    /// What `ERR_print_errors` writes, which empties the queue: a line
    /// `"%lu:%s:%s:%d:%s\n"` per error with the thread id, the
    /// `ERR_error_string_n` text, the file, the line, and the error's
    /// data (none of the errors recorded here has any).
    pub fn print(&mut self) -> String {
        let tid = thread_id();
        let mut out = String::new();
        for e in self.0.drain(..) {
            out.push_str(&format!("{}:{}:{}:{}:\n", tid, error_string(e.code), e.file, e.line));
        }
        out
    }
}

/// `CRYPTO_THREAD_get_current_id()` as `ERR_print_errors` prints it: the
/// calling thread's `pthread_t`.
fn thread_id() -> u64 {
    // SAFETY: pthread_self has no preconditions and cannot fail.
    #[allow(clippy::unnecessary_cast)]
    let id = unsafe { libc::pthread_self() } as u64;
    id
}

/// `ERR_GET_REASON`.
pub(crate) fn reason(code: u32) -> u32 {
    code & 0xfff
}

/// `ERR_GET_LIB`.
pub(crate) fn lib(code: u32) -> u32 {
    (code >> 24) & 0xff
}

/// `ERR_error_string_n(code, buf, 256)`: `error:%08lX:lib:func:reason`,
/// with `lib(%lu)`, `func(%lu)`, and `reason(%lu)` for codes without a
/// text (so no error at all is `error:00000000:lib(0):func(0):reason(0)`).
pub fn error_string(code: u32) -> String {
    let (l, f, r) = (lib(code), (code >> 12) & 0xfff, reason(code));
    let ls = lib_string(l).map(str::to_string).unwrap_or_else(|| format!("lib({})", l));
    let fs = func_string(l, f).map(str::to_string).unwrap_or_else(|| format!("func({})", f));
    let rs = reason_string(l, r).map(str::to_string).unwrap_or_else(|| format!("reason({})", r));
    format!("error:{:08X}:{}:{}:{}", code, ls, fs, rs)
}

fn lib_string(l: u32) -> Option<&'static str> {
    Some(match l {
        LIB_BN => "bignum routines",
        LIB_RSA => "rsa routines",
        LIB_EVP => "digital envelope routines",
        LIB_PEM => "PEM routines",
        LIB_ASN1 => "asn1 encoding routines",
        LIB_RAND => "random number generator",
        LIB_UI => "UI routines",
        _ => return None,
    })
}

fn func_string(l: u32, f: u32) -> Option<&'static str> {
    Some(match (l, f) {
        (LIB_ASN1, asn1::F_ASN1_CHECK_TLEN) => "asn1_check_tlen",
        (LIB_ASN1, asn1::F_ASN1_COLLECT) => "asn1_collect",
        (LIB_ASN1, asn1::F_ASN1_D2I_EX_PRIMITIVE) => "asn1_d2i_ex_primitive",
        (LIB_ASN1, asn1::F_ASN1_EX_C2I) => "asn1_ex_c2i",
        (LIB_ASN1, asn1::F_ASN1_FIND_END) => "asn1_find_end",
        (LIB_ASN1, asn1::F_ASN1_GET_OBJECT) => "ASN1_get_object",
        (LIB_ASN1, asn1::F_ASN1_ITEM_EMBED_D2I) => "asn1_item_embed_d2i",
        (LIB_ASN1, asn1::F_ASN1_TEMPLATE_EX_D2I) => "asn1_template_ex_d2i",
        (LIB_ASN1, asn1::F_ASN1_TEMPLATE_NOEXP_D2I) => "asn1_template_noexp_d2i",
        (LIB_ASN1, asn1::F_C2I_ASN1_BIT_STRING) => "c2i_ASN1_BIT_STRING",
        (LIB_ASN1, asn1::F_C2I_ASN1_OBJECT) => "c2i_ASN1_OBJECT",
        (LIB_ASN1, asn1::F_C2I_IBUF) => "c2i_ibuf",
        (LIB_ASN1, asn1::F_X509_NAME_EX_D2I) => "x509_name_ex_d2i",
        (LIB_ASN1, asn1::F_ASN1_MBSTRING_NCOPY) => "ASN1_mbstring_ncopy",
        (LIB_PEM, pem::F_GET_NAME) => "get_name",
        (LIB_PEM, pem::F_GET_HEADER_AND_DATA) => "get_header_and_data",
        (LIB_PEM, pem::F_PEM_READ_BIO_EX) => "PEM_read_bio_ex",
        (LIB_PEM, pem::F_PEM_ASN1_READ_BIO) => "PEM_ASN1_read_bio",
        (LIB_PEM, pem::F_PEM_GET_EVP_CIPHER_INFO) => "PEM_get_EVP_CIPHER_INFO",
        (LIB_PEM, pem::F_LOAD_IV) => "load_iv",
        (LIB_PEM, pem::F_PEM_DO_HEADER) => "PEM_do_header",
        (LIB_PEM, pem::F_PEM_DEF_CALLBACK) => "PEM_def_callback",
        (LIB_EVP, evp::F_EVP_DECRYPTFINAL_EX) => "EVP_DecryptFinal_ex",
        (LIB_RAND, rand::F_RAND_DRBG_INSTANTIATE) => "RAND_DRBG_instantiate",
        (LIB_RAND, rand::F_RAND_DRBG_GENERATE) => "RAND_DRBG_generate",
        (LIB_RSA, rsa::F_RSA_OSSL_PUBLIC_ENCRYPT) => "rsa_ossl_public_encrypt",
        (LIB_RSA, rsa::F_RSA_PADDING_ADD_PKCS1_TYPE_2) => "RSA_padding_add_PKCS1_type_2",
        (LIB_BN, bn::F_BN_MOD_INVERSE) => "BN_mod_inverse",
        (LIB_UI, ui::F_UI_PROCESS) => "UI_process",
        _ => return None,
    })
}

fn reason_string(l: u32, r: u32) -> Option<&'static str> {
    let s = match (l, r) {
        (LIB_ASN1, asn1::R_BAD_OBJECT_HEADER) => "bad object header",
        (LIB_ASN1, asn1::R_BAD_TEMPLATE) => "bad template",
        (LIB_ASN1, asn1::R_BMPSTRING_IS_WRONG_LENGTH) => "bmpstring is wrong length",
        (LIB_ASN1, asn1::R_BOOLEAN_IS_WRONG_LENGTH) => "boolean is wrong length",
        (LIB_ASN1, asn1::R_EXPLICIT_LENGTH_MISMATCH) => "explicit length mismatch",
        (LIB_ASN1, asn1::R_EXPLICIT_TAG_NOT_CONSTRUCTED) => "explicit tag not constructed",
        (LIB_ASN1, asn1::R_FIELD_MISSING) => "field missing",
        (LIB_ASN1, asn1::R_HEADER_TOO_LONG) => "header too long",
        (LIB_ASN1, asn1::R_ILLEGAL_OPTIONAL_ANY) => "illegal optional any",
        (LIB_ASN1, asn1::R_ILLEGAL_PADDING) => "illegal padding",
        (LIB_ASN1, asn1::R_ILLEGAL_TAGGED_ANY) => "illegal tagged any",
        (LIB_ASN1, asn1::R_ILLEGAL_ZERO_CONTENT) => "illegal zero content",
        (LIB_ASN1, asn1::R_INVALID_BIT_STRING_BITS_LEFT) => "invalid bit string bits left",
        (LIB_ASN1, asn1::R_INVALID_BMPSTRING_LENGTH) => "invalid bmpstring length",
        (LIB_ASN1, asn1::R_INVALID_OBJECT_ENCODING) => "invalid object encoding",
        (LIB_ASN1, asn1::R_INVALID_UNIVERSALSTRING_LENGTH) => "invalid universalstring length",
        (LIB_ASN1, asn1::R_INVALID_UTF8STRING) => "invalid utf8string",
        (LIB_ASN1, asn1::R_MISSING_EOC) => "missing eoc",
        (LIB_ASN1, asn1::R_MSTRING_NOT_UNIVERSAL) => "mstring not universal",
        (LIB_ASN1, asn1::R_MSTRING_WRONG_TAG) => "mstring wrong tag",
        (LIB_ASN1, asn1::R_NESTED_ASN1_STRING) => "nested asn1 string",
        (LIB_ASN1, asn1::R_NESTED_TOO_DEEP) => "nested too deep",
        (LIB_ASN1, asn1::R_NO_MATCHING_CHOICE_TYPE) => "no matching choice type",
        (LIB_ASN1, asn1::R_NULL_IS_WRONG_LENGTH) => "null is wrong length",
        (LIB_ASN1, asn1::R_SEQUENCE_LENGTH_MISMATCH) => "sequence length mismatch",
        (LIB_ASN1, asn1::R_SEQUENCE_NOT_CONSTRUCTED) => "sequence not constructed",
        (LIB_ASN1, asn1::R_STRING_TOO_LONG) => "string too long",
        (LIB_ASN1, asn1::R_STRING_TOO_SHORT) => "string too short",
        (LIB_ASN1, asn1::R_TOO_LONG) => "too long",
        (LIB_ASN1, asn1::R_TYPE_NOT_CONSTRUCTED) => "type not constructed",
        (LIB_ASN1, asn1::R_TYPE_NOT_PRIMITIVE) => "type not primitive",
        (LIB_ASN1, asn1::R_UNEXPECTED_EOC) => "unexpected eoc",
        (LIB_ASN1, asn1::R_UNIVERSALSTRING_IS_WRONG_LENGTH) => "universalstring is wrong length",
        (LIB_ASN1, asn1::R_WRONG_TAG) => "wrong tag",
        (LIB_ASN1, asn1::R_ILLEGAL_OPTIONS_ON_ITEM_TEMPLATE) => "illegal options on item template",
        (LIB_PEM, pem::R_NO_START_LINE) => "no start line",
        (LIB_PEM, pem::R_BAD_END_LINE) => "bad end line",
        (LIB_PEM, pem::R_BAD_BASE64_DECODE) => "bad base64 decode",
        (LIB_PEM, pem::R_NOT_PROC_TYPE) => "not proc type",
        (LIB_PEM, pem::R_NOT_ENCRYPTED) => "not encrypted",
        (LIB_PEM, pem::R_SHORT_HEADER) => "short header",
        (LIB_PEM, pem::R_NOT_DEK_INFO) => "not dek info",
        (LIB_PEM, pem::R_UNSUPPORTED_ENCRYPTION) => "unsupported encryption",
        (LIB_PEM, pem::R_MISSING_DEK_IV) => "missing dek iv",
        (LIB_PEM, pem::R_UNEXPECTED_DEK_IV) => "unexpected dek iv",
        (LIB_PEM, pem::R_BAD_IV_CHARS) => "bad iv chars",
        (LIB_PEM, pem::R_BAD_PASSWORD_READ) => "bad password read",
        (LIB_PEM, pem::R_PROBLEMS_GETTING_PASSWORD) => "problems getting password",
        (LIB_EVP, evp::R_BAD_DECRYPT) => "bad decrypt",
        (LIB_EVP, evp::R_WRONG_FINAL_BLOCK_LENGTH) => "wrong final block length",
        (LIB_RAND, rand::R_ERROR_RETRIEVING_ENTROPY) => "error retrieving entropy",
        (LIB_RAND, rand::R_IN_ERROR_STATE) => "in error state",
        (LIB_RSA, rsa::R_MODULUS_TOO_LARGE) => "modulus too large",
        (LIB_RSA, rsa::R_BAD_E_VALUE) => "bad e value",
        (LIB_RSA, rsa::R_DATA_TOO_LARGE_FOR_KEY_SIZE) => "data too large for key size",
        (LIB_RSA, rsa::R_DATA_TOO_LARGE_FOR_MODULUS) => "data too large for modulus",
        (LIB_BN, bn::R_NO_INVERSE) => "no inverse",
        (LIB_UI, ui::R_PROCESSING_ERROR) => "processing error",
        // ERR_reason_error_string falls back to the reasons common to
        // every library.
        (_, R_NESTED_ASN1_ERROR) => "nested asn1 error",
        (_, R_ASN1_LIB) => "ASN1 lib",
        _ => return None,
    };
    Some(s)
}

/// ASN1 library codes (`asn1err.h`).
pub(crate) mod asn1 {
    pub const F_ASN1_CHECK_TLEN: u32 = 104;
    pub const F_ASN1_COLLECT: u32 = 106;
    pub const F_ASN1_D2I_EX_PRIMITIVE: u32 = 108;
    pub const F_ASN1_EX_C2I: u32 = 204;
    pub const F_ASN1_FIND_END: u32 = 190;
    pub const F_ASN1_GET_OBJECT: u32 = 114;
    pub const F_ASN1_ITEM_EMBED_D2I: u32 = 120;
    pub const F_ASN1_TEMPLATE_EX_D2I: u32 = 132;
    pub const F_ASN1_TEMPLATE_NOEXP_D2I: u32 = 131;
    pub const F_C2I_ASN1_BIT_STRING: u32 = 189;
    pub const F_C2I_ASN1_OBJECT: u32 = 196;
    pub const F_C2I_IBUF: u32 = 226;
    pub const F_X509_NAME_EX_D2I: u32 = 158;
    pub const F_ASN1_MBSTRING_NCOPY: u32 = 122;

    pub const R_BAD_OBJECT_HEADER: u32 = 102;
    pub const R_BAD_TEMPLATE: u32 = 230;
    pub const R_BMPSTRING_IS_WRONG_LENGTH: u32 = 214;
    pub const R_BOOLEAN_IS_WRONG_LENGTH: u32 = 106;
    pub const R_EXPLICIT_LENGTH_MISMATCH: u32 = 119;
    pub const R_EXPLICIT_TAG_NOT_CONSTRUCTED: u32 = 120;
    pub const R_FIELD_MISSING: u32 = 121;
    pub const R_HEADER_TOO_LONG: u32 = 123;
    pub const R_ILLEGAL_OPTIONAL_ANY: u32 = 126;
    pub const R_ILLEGAL_PADDING: u32 = 221;
    pub const R_ILLEGAL_TAGGED_ANY: u32 = 127;
    pub const R_ILLEGAL_ZERO_CONTENT: u32 = 222;
    pub const R_INVALID_BIT_STRING_BITS_LEFT: u32 = 220;
    pub const R_INVALID_BMPSTRING_LENGTH: u32 = 129;
    pub const R_INVALID_OBJECT_ENCODING: u32 = 216;
    pub const R_INVALID_UNIVERSALSTRING_LENGTH: u32 = 133;
    pub const R_INVALID_UTF8STRING: u32 = 134;
    pub const R_MISSING_EOC: u32 = 137;
    pub const R_MSTRING_NOT_UNIVERSAL: u32 = 139;
    pub const R_MSTRING_WRONG_TAG: u32 = 140;
    pub const R_NESTED_ASN1_STRING: u32 = 197;
    pub const R_NESTED_TOO_DEEP: u32 = 201;
    pub const R_NO_MATCHING_CHOICE_TYPE: u32 = 143;
    pub const R_NULL_IS_WRONG_LENGTH: u32 = 144;
    pub const R_SEQUENCE_LENGTH_MISMATCH: u32 = 148;
    pub const R_SEQUENCE_NOT_CONSTRUCTED: u32 = 149;
    pub const R_STRING_TOO_LONG: u32 = 151;
    pub const R_STRING_TOO_SHORT: u32 = 152;
    pub const R_TOO_LONG: u32 = 155;
    pub const R_TYPE_NOT_CONSTRUCTED: u32 = 156;
    pub const R_TYPE_NOT_PRIMITIVE: u32 = 195;
    pub const R_UNEXPECTED_EOC: u32 = 159;
    pub const R_UNIVERSALSTRING_IS_WRONG_LENGTH: u32 = 215;
    pub const R_WRONG_TAG: u32 = 168;
    pub const R_ILLEGAL_OPTIONS_ON_ITEM_TEMPLATE: u32 = 170;
}

/// PEM library codes (`pemerr.h`).
pub(crate) mod pem {
    pub const F_GET_NAME: u32 = 144;
    pub const F_GET_HEADER_AND_DATA: u32 = 143;
    pub const F_PEM_READ_BIO_EX: u32 = 145;
    pub const F_PEM_ASN1_READ_BIO: u32 = 103;
    pub const F_PEM_GET_EVP_CIPHER_INFO: u32 = 107;
    pub const F_LOAD_IV: u32 = 101;
    pub const F_PEM_DO_HEADER: u32 = 106;
    pub const F_PEM_DEF_CALLBACK: u32 = 100;

    pub const R_NO_START_LINE: u32 = 108;
    pub const R_BAD_END_LINE: u32 = 102;
    pub const R_BAD_BASE64_DECODE: u32 = 100;
    pub const R_NOT_PROC_TYPE: u32 = 107;
    pub const R_NOT_ENCRYPTED: u32 = 106;
    pub const R_SHORT_HEADER: u32 = 112;
    pub const R_NOT_DEK_INFO: u32 = 105;
    pub const R_UNSUPPORTED_ENCRYPTION: u32 = 114;
    pub const R_MISSING_DEK_IV: u32 = 129;
    pub const R_UNEXPECTED_DEK_IV: u32 = 130;
    pub const R_BAD_IV_CHARS: u32 = 103;
    pub const R_BAD_PASSWORD_READ: u32 = 104;
    pub const R_PROBLEMS_GETTING_PASSWORD: u32 = 109;
}

/// EVP library codes (`evperr.h`).
pub(crate) mod evp {
    pub const F_EVP_DECRYPTFINAL_EX: u32 = 101;
    pub const R_BAD_DECRYPT: u32 = 100;
    pub const R_WRONG_FINAL_BLOCK_LENGTH: u32 = 109;
}

/// RAND library codes (`randerr.h`).
pub(crate) mod rand {
    pub const F_RAND_DRBG_INSTANTIATE: u32 = 108;
    pub const F_RAND_DRBG_GENERATE: u32 = 107;
    pub const R_ERROR_RETRIEVING_ENTROPY: u32 = 110;
    pub const R_IN_ERROR_STATE: u32 = 114;
}

/// RSA library codes (`rsaerr.h`).
pub(crate) mod rsa {
    pub const F_RSA_OSSL_PUBLIC_ENCRYPT: u32 = 104;
    pub const F_RSA_PADDING_ADD_PKCS1_TYPE_2: u32 = 109;
    pub const R_MODULUS_TOO_LARGE: u32 = 105;
    pub const R_BAD_E_VALUE: u32 = 101;
    pub const R_DATA_TOO_LARGE_FOR_KEY_SIZE: u32 = 110;
    pub const R_DATA_TOO_LARGE_FOR_MODULUS: u32 = 132;
}

/// BN library codes (`bnerr.h`).
pub(crate) mod bn {
    pub const F_BN_MOD_INVERSE: u32 = 110;
    pub const R_NO_INVERSE: u32 = 108;
}

/// UI library codes (`uierr.h`).
pub(crate) mod ui {
    pub const F_UI_PROCESS: u32 = 113;
    pub const R_PROCESSING_ERROR: u32 = 107;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_texts() {
        // Texts as 1.1.1t's ERR_error_string_n writes them.
        assert_eq!(error_string(0), "error:00000000:lib(0):func(0):reason(0)");
        assert_eq!(
            error_string(pack(LIB_PEM, pem::F_GET_NAME, pem::R_NO_START_LINE)),
            "error:0909006C:PEM routines:get_name:no start line"
        );
        assert_eq!(
            error_string(pack(LIB_ASN1, asn1::F_ASN1_CHECK_TLEN, asn1::R_WRONG_TAG)),
            "error:0D0680A8:asn1 encoding routines:asn1_check_tlen:wrong tag"
        );
        assert_eq!(
            error_string(pack(LIB_ASN1, asn1::F_ASN1_GET_OBJECT, asn1::R_TOO_LONG)),
            "error:0D07209B:asn1 encoding routines:ASN1_get_object:too long"
        );
        assert_eq!(
            error_string(pack(LIB_EVP, evp::F_EVP_DECRYPTFINAL_EX, evp::R_BAD_DECRYPT)),
            "error:06065064:digital envelope routines:EVP_DecryptFinal_ex:bad decrypt"
        );
        assert_eq!(
            error_string(pack(LIB_EVP, evp::F_EVP_DECRYPTFINAL_EX, evp::R_WRONG_FINAL_BLOCK_LENGTH)),
            "error:0606506D:digital envelope routines:EVP_DecryptFinal_ex:wrong final block length"
        );
        assert_eq!(error_string(pack(77, 5, 6)), "error:4D005006:lib(77):func(5):reason(6)");
    }

    #[test]
    fn queue_order_and_print() {
        let mut e = Errs::new();
        assert_eq!(e.peek(), 0);
        e.put(LIB_PEM, pem::F_GET_NAME, pem::R_NO_START_LINE, "crypto/pem/pem_lib.c", 745);
        e.put(LIB_EVP, evp::F_EVP_DECRYPTFINAL_EX, evp::R_BAD_DECRYPT, "crypto/evp/evp_enc.c", 612);
        assert_eq!(e.peek(), 0x0909006C);
        assert_eq!(e.last(), 0x06065064);
        let printed = e.clone().print();
        let tid = thread_id();
        assert_eq!(
            printed,
            format!(
                "{tid}:error:0909006C:PEM routines:get_name:no start line:crypto/pem/pem_lib.c:745:\n\
                 {tid}:error:06065064:digital envelope routines:EVP_DecryptFinal_ex:bad decrypt:crypto/evp/evp_enc.c:612:\n"
            )
        );
        assert_eq!(e.get(), 0x0909006C);
        assert_eq!(e.get(), 0x06065064);
        assert_eq!(e.get(), 0);
    }
}
