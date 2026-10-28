//! Platform layer: the only place Windows APIs are touched.
//! DiagKit's one platform question is "what does this file's
//! version resource say?" (FileVersion, ProductVersion, …).
//! On non-Windows targets there is no version resource, and
//! the honest answer is `None` — the manifest then carries
//! size + SHA-256 only, exactly as documented. That is a
//! normal result, NOT an ERR_NOT_SUPPORTED: the collection
//! itself is fully portable.
//!
//! Every extern block MUST carry #[link(name = "...")] naming
//! its import library. Without it the build fails at LINK
//! time with LNK2019 — check and clippy cannot catch it; CI's
//! real build can.

use std::path::Path;

#[cfg(windows)]
use crate::ERR_PLATFORM;

pub type PResult<T> = Result<T, (i32, String)>;

/// The version-resource fields DiagKit reports, in manifest
/// order. Absent/empty fields are omitted.
#[cfg(windows)]
const VERSION_KEYS: [&str; 7] = [
    "CompanyName",
    "FileDescription",
    "FileVersion",
    "ProductName",
    "ProductVersion",
    "LegalCopyright",
    "OriginalFilename",
];

/// Read a file's version-resource strings on Windows.
/// `Ok(None)` when the file carries no version resource (or
/// the platform is not Windows); `Err(ERR_PLATFORM)` when the
/// OS calls fail in a way that isn't "no resource".
#[cfg(windows)]
pub fn version_strings(path: &Path) -> PResult<Option<Vec<(String, String)>>> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    #[link(name = "version")]
    extern "system" {
        fn GetFileVersionInfoSizeW(filename: *const u16, handle: *mut u32) -> u32;
        fn GetFileVersionInfoW(filename: *const u16, handle: u32, len: u32, data: *mut u8) -> i32;
        fn VerQueryValueW(
            block: *const u8,
            sub_block: *const u16,
            buffer: *mut *const core::ffi::c_void,
            len: *mut u32,
        ) -> i32;
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    let path_wide: Vec<u16> = OsStr::new(path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    // SAFETY: all pointers below are to live local buffers;
    // the version-info block is kept alive in `data` while
    // VerQueryValueW hands out pointers into it, and each
    // returned string is copied out before the next call.
    unsafe {
        let mut handle = 0u32;
        let size = GetFileVersionInfoSizeW(path_wide.as_ptr(), &mut handle);
        if size == 0 {
            // The overwhelmingly common cause is "this file
            // has no version resource" — a normal None.
            return Ok(None);
        }
        let mut data = vec![0u8; size as usize];
        if GetFileVersionInfoW(path_wide.as_ptr(), 0, size, data.as_mut_ptr()) == 0 {
            return Err((
                ERR_PLATFORM,
                format!("GetFileVersionInfoW failed for {}", path.display()),
            ));
        }
        let block = data.as_ptr() as *const core::ffi::c_void;

        // Language + codepage pairs, in resource order.
        let mut translations: Vec<(u16, u16)> = Vec::new();
        let mut out_ptr: *const core::ffi::c_void = std::ptr::null();
        let mut out_len: u32 = 0;
        let query = wide("\\VarFileInfo\\Translation");
        if VerQueryValueW(
            block as *const u8,
            query.as_ptr(),
            &mut out_ptr,
            &mut out_len,
        ) != 0
            && out_len >= 4
        {
            let words = std::slice::from_raw_parts(out_ptr as *const u16, (out_len / 2) as usize);
            for pair in words.chunks_exact(2) {
                translations.push((pair[0], pair[1]));
            }
        }
        if translations.is_empty() {
            // Common fallbacks: US English / Unicode, then
            // US English / neutral.
            translations.push((0x0409, 0x04B0));
            translations.push((0x0409, 0x0000));
        }

        let mut pairs: Vec<(String, String)> = Vec::new();
        'outer: for (lang, cp) in &translations {
            for key in VERSION_KEYS {
                let sub = wide(&format!("\\StringFileInfo\\{lang:04x}{cp:04x}\\{key}"));
                let mut p: *const core::ffi::c_void = std::ptr::null();
                let mut len: u32 = 0;
                if VerQueryValueW(block as *const u8, sub.as_ptr(), &mut p, &mut len) != 0
                    && len > 0
                    && !p.is_null()
                {
                    let chars = std::slice::from_raw_parts(p as *const u16, len as usize);
                    let text: String = String::from_utf16_lossy(chars)
                        .trim_end_matches('\0')
                        .trim()
                        .to_string();
                    if !text.is_empty() && !pairs.iter().any(|(k, _)| k == key) {
                        pairs.push((key.to_string(), text));
                    }
                }
            }
            if !pairs.is_empty() {
                break 'outer;
            }
        }
        if pairs.is_empty() {
            Ok(None)
        } else {
            Ok(Some(pairs))
        }
    }
}

#[cfg(not(windows))]
pub fn version_strings(_path: &Path) -> PResult<Option<Vec<(String, String)>>> {
    // No version resources off Windows: size + SHA-256 only,
    // as documented. Not an error.
    Ok(None)
}
