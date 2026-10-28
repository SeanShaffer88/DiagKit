//! C ABI surface — everything declared in include/diagkit.h.
//! Conventions (house standard):
//! - `*mut c_char` results are caller-owned; free with
//!   `di_free_string`.
//! - `di_collect` returns NULL on failure and sets the
//!   thread-local last-error (code + message), readable via
//!   `di_last_error()` / `di_last_error_code()`.
//! - Nothing unwinds across the FFI boundary (catch_unwind
//!   everywhere; release profile also sets panic = "abort").

// The exported functions ARE the raw-pointer C ABI declared
// in include/diagkit.h; pointer validity is the documented
// contract.
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::cell::RefCell;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::panic::catch_unwind;

use crate::{DI_OK, ERR_INTERNAL, ERR_INVALID_ARG};

thread_local! {
    static LAST_ERROR: RefCell<(i32, CString)> =
        RefCell::new((0, CString::new("").unwrap()));
}

pub fn set_error(code: i32, msg: &str) {
    let clean: String = msg.chars().filter(|&c| c != '\0').collect();
    LAST_ERROR.with(|e| {
        *e.borrow_mut() = (
            code,
            CString::new(clean).unwrap_or_else(|_| CString::new("error").unwrap()),
        );
    });
}

fn clear_error() {
    set_error(DI_OK, "");
}

fn panic_failure() -> *mut c_char {
    set_error(ERR_INTERNAL, "internal panic caught at the FFI boundary");
    std::ptr::null_mut()
}

#[no_mangle]
pub extern "C" fn di_version() -> *const c_char {
    static VERSION_C: &[u8] = b"0.1.0\0";
    VERSION_C.as_ptr() as *const c_char
}

#[no_mangle]
pub extern "C" fn di_last_error() -> *const c_char {
    LAST_ERROR.with(|e| e.borrow().1.as_ptr())
}

#[no_mangle]
pub extern "C" fn di_last_error_code() -> c_int {
    LAST_ERROR.with(|e| e.borrow().0) as c_int
}

/// # Safety (caller contract): `p` is null or a string this
/// library returned and has not been freed yet. Documented
/// in the header.
#[no_mangle]
pub extern "C" fn di_free_string(p: *mut c_char) {
    if !p.is_null() {
        unsafe {
            drop(CString::from_raw(p));
        }
    }
}

fn collect_impl(spec_json: *const c_char) -> *mut c_char {
    if spec_json.is_null() {
        set_error(ERR_INVALID_ARG, "spec_json must not be null");
        return std::ptr::null_mut();
    }
    let text = match unsafe { CStr::from_ptr(spec_json) }.to_str() {
        Ok(t) => t,
        Err(_) => {
            set_error(ERR_INVALID_ARG, "spec_json must be valid UTF-8");
            return std::ptr::null_mut();
        }
    };
    match crate::collect(text) {
        Ok(result) => match CString::new(result.to_json()) {
            Ok(s) => {
                clear_error();
                s.into_raw()
            }
            Err(_) => {
                set_error(ERR_INTERNAL, "result string contained a NUL byte");
                std::ptr::null_mut()
            }
        },
        Err((code, msg)) => {
            set_error(code, &msg);
            std::ptr::null_mut()
        }
    }
}

/// Collect a diagnostics bundle from a spec JSON object.
/// Returns a caller-owned result JSON string
/// (`{"zip":…,"entries":…,"bytes":…}`), or NULL on failure
/// with the last-error set. See include/diagkit.h for the
/// full spec.
#[no_mangle]
pub extern "C" fn di_collect(spec_json: *const c_char) -> *mut c_char {
    match catch_unwind(|| collect_impl(spec_json)) {
        Ok(p) => p,
        Err(_) => panic_failure(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    fn cs(s: &str) -> CString {
        CString::new(s).unwrap()
    }

    fn take_string(p: *mut c_char) -> String {
        assert!(!p.is_null());
        let s = unsafe { CStr::from_ptr(p) }.to_str().unwrap().to_string();
        di_free_string(p);
        s
    }

    #[test]
    fn ffi_version_and_error_surface() {
        let v = unsafe { CStr::from_ptr(di_version()) }.to_str().unwrap();
        assert_eq!(v, "0.1.0");
        di_free_string(std::ptr::null_mut()); // no-op, must not crash
    }

    #[test]
    fn ffi_collect_errors() {
        // Null spec.
        assert!(di_collect(std::ptr::null()).is_null());
        assert_eq!(di_last_error_code(), ERR_INVALID_ARG as c_int);
        // Malformed JSON -> DI_ERR_PARSE.
        let bad = cs(r#"{"output_zip":"#);
        assert!(di_collect(bad.as_ptr()).is_null());
        assert_eq!(di_last_error_code(), crate::ERR_PARSE as c_int);
        // Missing output_zip -> DI_ERR_INVALID_ARG, message set.
        let empty = cs("{}");
        assert!(di_collect(empty.as_ptr()).is_null());
        assert_eq!(di_last_error_code(), ERR_INVALID_ARG as c_int);
        let msg = unsafe { CStr::from_ptr(di_last_error()) }.to_str().unwrap();
        assert!(msg.contains("output_zip"), "message was: {msg}");
    }

    #[test]
    fn ffi_collect_end_to_end() {
        let dir = std::env::temp_dir().join(format!("diagkit-ffi-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("app.log");
        std::fs::write(&log, b"ffi bytes").unwrap();
        let out = dir.join("out.zip");
        let spec = cs(&format!(
            "{{\"output_zip\":\"{}\",\"files\":[\"{}\"]}}",
            crate::json_escape(&out.to_string_lossy()),
            crate::json_escape(&log.to_string_lossy())
        ));
        let result = take_string(di_collect(spec.as_ptr()));
        let v = crate::json::parse(&result).unwrap();
        assert_eq!(v.get("entries").unwrap().as_i64(), Some(2));
        assert!(v.get("bytes").unwrap().as_i64().unwrap() > 0);
        assert_eq!(di_last_error_code(), DI_OK as c_int);
        assert!(out.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
