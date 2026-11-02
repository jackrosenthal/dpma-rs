//! The module's registration with Asterisk's loader.

use crate::sys;
use crate::util::CStatic;
use std::os::raw::{c_char, c_void};
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};

/// A module's `struct ast_module_info`, in writable memory: the loader
/// sets its `self` field.
pub type ModuleInfo = CStatic<sys::ast_module_info>;

/// The module's info, set by the constructor `asterisk_module!` emits.
static INFO: AtomicPtr<sys::ast_module_info> = AtomicPtr::new(std::ptr::null_mut());

/// The constructor's work (`__reg_module`): remember `info` and register
/// it with the loader (`ast_module_register`), which is loading this
/// module's image right now.
///
/// # Safety
/// Only for the constructor `asterisk_module!` emits.
#[doc(hidden)]
pub unsafe fn register(info: &'static ModuleInfo) {
    INFO.store(info.get(), Ordering::SeqCst);
    sys::ast_module_register(info.get());
}

/// The destructor's work (`__unreg_module`): `ast_module_unregister`.
///
/// # Safety
/// Only for the destructor `asterisk_module!` emits.
#[doc(hidden)]
pub unsafe fn unregister(info: &'static ModuleInfo) {
    sys::ast_module_unregister(info.get());
}

/// `AST_MODULE_SELF`: the loader's handle of this module (NULL before the
/// loader has set it).
pub fn self_ptr() -> *mut sys::ast_module {
    let info = INFO.load(Ordering::SeqCst);
    if info.is_null() {
        return std::ptr::null_mut();
    }
    // SAFETY: `info` is the module's static info; the loader writes `self`
    // before it starts the module and the field is read as a whole.
    unsafe { std::ptr::addr_of!((*info).self_).read_volatile() }
}

/// `AST_MODULE`: the module's name (for module debug levels), "" before
/// the constructor ran.
pub fn name() -> *const c_char {
    let info = INFO.load(Ordering::SeqCst);
    if info.is_null() {
        return c"".as_ptr();
    }
    // SAFETY: `name` is a static string set at compile time.
    unsafe { (*info).name }
}

/// Call first thing in the module's `load` callback.
///
/// Rust's standard library registers thread-local destructors
/// (`__cxa_thread_atexit_impl`) on the Asterisk threads that run the
/// module's code, for example on the thread that loads the module when it
/// spawns a thread, and glibc keeps a shared object mapped while any are
/// pending.  So `module unload` usually leaves the module mapped: the
/// loader's `dlclose` drops the last reference, but the image stays and
/// its destructor, which would unregister the module from the loader, does
/// not run.  The next `module load` then finds the module still registered
/// and starts it again without a `dlopen`, and the unload after that calls
/// `dlclose` on a handle that is no longer open ("Failure in dlclose ...
/// shared object not open").  So when the module is started again in the
/// same image, this takes the reference that the loader's next `dlclose`
/// drops.  (A new build still needs an Asterisk restart.)
pub fn reopen_if_restarted() {
    static STARTED_BEFORE: AtomicBool = AtomicBool::new(false);
    if STARTED_BEFORE.swap(true, Ordering::SeqCst) {
        reopen();
    }
}

fn reopen() {
    // SAFETY: dladdr fills `info` for an address inside this image (this
    // function); dlopen with RTLD_NOLOAD only adds a reference to an image
    // that is already loaded, and the loader's next dlclose releases it.
    unsafe {
        let mut info: libc::Dl_info = std::mem::zeroed();
        if libc::dladdr(reopen as *const c_void, &mut info) == 0 || info.dli_fname.is_null() {
            return;
        }
        if libc::dlopen(info.dli_fname, libc::RTLD_LAZY | libc::RTLD_NOLOAD).is_null() {
            let err = crate::util::from_ptr(libc::dlerror()).unwrap_or_default();
            let name = crate::util::from_ptr(info.dli_fname).unwrap_or_default();
            crate::ast_log!(
                crate::log::LOG_WARNING,
                "Unable to reference {}: {}",
                name,
                err
            );
        }
    }
}

/// Declare an Asterisk module, as `AST_MODULE_INFO` does in C: the
/// `struct ast_module_info`, a constructor that registers it with the
/// loader when the image is loaded (`.init_array`), a destructor that
/// unregisters it (`.fini_array`), and the `AST_MODULE_SELF_SYM` function
/// `__internal_<name>_self`.
///
/// ```ignore
/// dpma_ast::asterisk_module! {
///     name: "res_example",
///     description: "Example",
///     flags: dpma_ast::sys::AST_MODFLAG_LOAD_ORDER,
///     support_level: dpma_ast::sys::AST_MODULE_SUPPORT_EXTENDED,
///     load: load_module,
///     unload: unload_module,
///     reload: Some(reload_module),
///     load_pri: dpma_ast::sys::AST_MODPRI_DEFAULT,
///     requires: "res_pjsip",
///     optional_modules: "app_voicemail",
/// }
/// ```
///
/// `load` is an `unsafe extern "C" fn() -> ast_module_load_result`,
/// `unload` an `unsafe extern "C" fn() -> c_int`, and `reload` an
/// `Option` of one; `requires` and `optional_modules` are comma-separated
/// module names ("" for none).  A cdylib holds one module.
#[macro_export]
macro_rules! asterisk_module {
    (
        name: $name:literal,
        description: $description:literal,
        flags: $flags:expr,
        support_level: $support_level:expr,
        load: $load:expr,
        unload: $unload:expr,
        reload: $reload:expr,
        load_pri: $load_pri:expr,
        requires: $requires:literal,
        optional_modules: $optional_modules:literal $(,)?
    ) => {
        /// The module's `struct ast_module_info` (`__mod_info`).
        static __AST_MODULE_INFO: $crate::module::ModuleInfo =
            $crate::module::ModuleInfo::new($crate::sys::ast_module_info {
                self_: ::std::ptr::null_mut(),
                load: ::std::option::Option::Some($load),
                reload: $reload,
                unload: ::std::option::Option::Some($unload),
                name: concat!($name, "\0").as_ptr().cast(),
                description: concat!($description, "\0").as_ptr().cast(),
                key: $crate::sys::ASTERISK_GPL_KEY.as_ptr().cast(),
                flags: $flags as ::std::os::raw::c_uint,
                // Empty, as in the official DPMA: Asterisk's loader
                // compares the build options checksum only when a module
                // has one (`!ast_strlen_zero(mod->info->buildopt_sum) &&
                // strcmp(...)`, main/loader.c:1836 in 22, 23, and 24), so
                // the module loads into any build of a supported Asterisk.
                buildopt_sum: [0; 33],
                load_pri: $load_pri as ::std::os::raw::c_uchar,
                requires: if $requires.is_empty() {
                    ::std::ptr::null()
                } else {
                    concat!($requires, "\0").as_ptr().cast()
                },
                optional_modules: if $optional_modules.is_empty() {
                    ::std::ptr::null()
                } else {
                    concat!($optional_modules, "\0").as_ptr().cast()
                },
                enhances: ::std::ptr::null(),
                reserved1: ::std::ptr::null_mut(),
                reserved2: ::std::ptr::null_mut(),
                reserved3: ::std::ptr::null_mut(),
                reserved4: ::std::ptr::null_mut(),
                support_level: $support_level,
            });

        /// `__reg_module`, run when the image is loaded.
        #[used]
        #[unsafe(link_section = ".init_array")]
        static __AST_MODULE_REGISTER: unsafe extern "C" fn() = {
            unsafe extern "C" fn reg_module() {
                // SAFETY: runs once, from the dynamic loader, while
                // Asterisk's loader is loading this image.
                unsafe { $crate::module::register(&__AST_MODULE_INFO) }
            }
            reg_module
        };

        /// `__unreg_module`, run when the image is unloaded.
        #[used]
        #[unsafe(link_section = ".fini_array")]
        static __AST_MODULE_UNREGISTER: unsafe extern "C" fn() = {
            unsafe extern "C" fn unreg_module() {
                // SAFETY: runs once, from the dynamic loader, when the
                // image goes away.
                unsafe { $crate::module::unregister(&__AST_MODULE_INFO) }
            }
            unreg_module
        };

        /// `AST_MODULE_SELF_SYM`.
        #[unsafe(export_name = concat!("__internal_", $name, "_self"))]
        pub extern "C" fn __ast_module_self() -> *mut $crate::sys::ast_module {
            $crate::module::self_ptr()
        }
    };
}
