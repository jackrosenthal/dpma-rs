//! The error codes and texts of OpenSSL 1.1.1t, which the official DPMA
//! links statically.
//!
//! Where the official DPMA logs an OpenSSL error of its message encryption
//! or its common password, it formats an error code from 1.1.1t's
//! per-thread error queue: `ERR_error_string_n` or `ERR_print_errors`
//! (`log_ssl`).  The functions ported here that can fail that way record
//! the errors 1.1.1t would push, with its library, function, and reason
//! codes and its source file and line, in an error list, and the callers
//! format them the same way.
//!
//! One difference: 1.1.1t's queue is per thread and the official DPMA never
//! clears it, so its messages can name an error left over from an earlier
//! operation on the same thread.  Here each operation starts with an empty
//! list, so a message names the errors of the failure it reports.

/// `ERR_LIB_BN`.
pub(crate) const LIB_BN: u32 = 3;
/// `ERR_LIB_RSA`.
pub(crate) const LIB_RSA: u32 = 4;
/// `ERR_LIB_EVP`.
pub(crate) const LIB_EVP: u32 = 6;
/// `ERR_LIB_RAND`.
pub(crate) const LIB_RAND: u32 = 36;

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

    /// `ERR_peek_error`: the oldest error's code (0 when there is none).
    pub fn peek(&self) -> u32 {
        self.0.first().map(|e| e.code).unwrap_or(0)
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

/// `ERR_error_string_n(code, buf, 256)`: `error:%08lX:lib:func:reason`,
/// with `lib(%lu)`, `func(%lu)`, and `reason(%lu)` for codes without a
/// text (so no error at all is `error:00000000:lib(0):func(0):reason(0)`).
pub fn error_string(code: u32) -> String {
    let (l, f, r) = ((code >> 24) & 0xff, (code >> 12) & 0xfff, code & 0xfff);
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
        LIB_RAND => "random number generator",
        _ => return None,
    })
}

fn func_string(l: u32, f: u32) -> Option<&'static str> {
    Some(match (l, f) {
        (LIB_EVP, evp::F_EVP_DECRYPTFINAL_EX) => "EVP_DecryptFinal_ex",
        (LIB_RAND, rand::F_RAND_DRBG_INSTANTIATE) => "RAND_DRBG_instantiate",
        (LIB_RAND, rand::F_RAND_DRBG_GENERATE) => "RAND_DRBG_generate",
        (LIB_RSA, rsa::F_RSA_OSSL_PUBLIC_ENCRYPT) => "rsa_ossl_public_encrypt",
        (LIB_RSA, rsa::F_RSA_PADDING_ADD_PKCS1_TYPE_2) => "RSA_padding_add_PKCS1_type_2",
        (LIB_BN, bn::F_BN_MOD_INVERSE) => "BN_mod_inverse",
        _ => return None,
    })
}

fn reason_string(l: u32, r: u32) -> Option<&'static str> {
    let s = match (l, r) {
        (LIB_EVP, evp::R_BAD_DECRYPT) => "bad decrypt",
        (LIB_EVP, evp::R_WRONG_FINAL_BLOCK_LENGTH) => "wrong final block length",
        (LIB_RAND, rand::R_ERROR_RETRIEVING_ENTROPY) => "error retrieving entropy",
        (LIB_RAND, rand::R_IN_ERROR_STATE) => "in error state",
        (LIB_RSA, rsa::R_MODULUS_TOO_LARGE) => "modulus too large",
        (LIB_RSA, rsa::R_BAD_E_VALUE) => "bad e value",
        (LIB_RSA, rsa::R_DATA_TOO_LARGE_FOR_KEY_SIZE) => "data too large for key size",
        (LIB_RSA, rsa::R_DATA_TOO_LARGE_FOR_MODULUS) => "data too large for modulus",
        (LIB_BN, bn::R_NO_INVERSE) => "no inverse",
        _ => return None,
    };
    Some(s)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_texts() {
        // Texts as 1.1.1t's ERR_error_string_n writes them.
        assert_eq!(error_string(0), "error:00000000:lib(0):func(0):reason(0)");
        assert_eq!(
            error_string(pack(LIB_RAND, rand::F_RAND_DRBG_GENERATE, rand::R_IN_ERROR_STATE)),
            "error:2406B072:random number generator:RAND_DRBG_generate:in error state"
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
        e.put(LIB_RAND, rand::F_RAND_DRBG_GENERATE, rand::R_IN_ERROR_STATE, "crypto/rand/drbg_lib.c", 578);
        e.put(LIB_EVP, evp::F_EVP_DECRYPTFINAL_EX, evp::R_BAD_DECRYPT, "crypto/evp/evp_enc.c", 612);
        assert_eq!(e.peek(), 0x2406B072);
        let printed = e.print();
        let tid = thread_id();
        assert_eq!(
            printed,
            format!(
                "{tid}:error:2406B072:random number generator:RAND_DRBG_generate:in error state:crypto/rand/drbg_lib.c:578:\n\
                 {tid}:error:06065064:digital envelope routines:EVP_DecryptFinal_ex:bad decrypt:crypto/evp/evp_enc.c:612:\n"
            )
        );
        assert_eq!(e.peek(), 0);
    }
}
