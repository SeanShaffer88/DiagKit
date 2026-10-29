//! DiagKit — one-call diagnostics bundles behind a small C ABI.
//!
//! The problem this solves: when a field test fails, the
//! evidence hunt is a scavenger run — "send me the log", "what
//! version is the DLL, exactly", "hash the exe so I can tell
//! whether it's the build I think it is" — one question per
//! round trip, and the answer to each changes what the next
//! question has to be. DiagKit is the one call an app makes
//! (or a support flow asks for) that answers all of it at
//! once:
//!
//! - **Collect files** (logs, dumps, configs) into one ZIP.
//! - **A `manifest.json`** in the bundle records what is
//!   inside (name, size, SHA-256 per entry), plus whatever
//!   the caller asked about: per-file info (size, SHA-256,
//!   and — on Windows — the strings from a file's version
//!   resource), recursive directory *listings* (names and
//!   sizes, never contents), and a small environment block.
//! - **Caps, enforced twice.** One file may be at most
//!   64 MiB and the whole bundle at most 256 MiB; the plan
//!   is checked from file sizes before anything is read, and
//!   the running totals are checked again while streaming,
//!   so a file that grows mid-collection still cannot push
//!   the bundle past its cap. Breaking a cap is an error
//!   that names the file — never a silent truncation.
//! - **Safe entry names.** Stored files land under names
//!   derived from their canonical paths (no `..`, no leading
//!   `/`, no drive), and caller-chosen `extra_text` names are
//!   validated against the same rules and rejected when they
//!   break them.
//!
//! The ZIP writer (STORED entries, own CRC-32) lives in
//! `zip`; SHA-256 and CRC-32 in `hash`; the JSON engine in
//! `json`; the one platform question (version-resource
//! strings) in `platform`; the C ABI in `ffi`.

pub mod ffi;
pub mod hash;
pub mod json;
pub mod platform;
pub mod zip;

use std::collections::HashSet;
use std::path::{Component, Path, PathBuf};

pub const VERSION: &str = "0.1.0";
pub const VERSION_MAJOR: u32 = 0;
pub const VERSION_MINOR: u32 = 1;
pub const VERSION_PATCH: u32 = 0;

// Error codes (mirror include/diagkit.h).
pub const DI_OK: i32 = 0;
pub const ERR_INVALID_ARG: i32 = 1;
pub const ERR_NOT_SUPPORTED: i32 = 2;
pub const ERR_NOT_FOUND: i32 = 3;
pub const ERR_ACCESS_DENIED: i32 = 4;
pub const ERR_PLATFORM: i32 = 5;
pub const ERR_INTERNAL: i32 = 6;
pub const ERR_PARSE: i32 = 7;
pub const ERR_TOO_LARGE: i32 = 8;

pub type DiResult<T> = Result<T, (i32, String)>;

/// The name of the manifest entry inside every bundle. It is
/// reserved: no collected file or `extra_text` entry may use
/// it (a collected file that derives it is renamed by the
/// collision rule instead).
pub const MANIFEST_NAME: &str = "manifest.json";

/// One collected file may be at most this many bytes.
pub const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;
/// The whole bundle's stored content may be at most this.
pub const MAX_TOTAL_BYTES: u64 = 256 * 1024 * 1024;
/// A directory listing holds at most this many entries
/// (a per-directory `max_files` may ask for fewer).
pub const MAX_DIR_ENTRIES: usize = 5000;

/// Escape a string for inclusion inside JSON double quotes.
pub fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

fn io_code(e: &std::io::Error) -> i32 {
    match e.kind() {
        std::io::ErrorKind::NotFound => ERR_NOT_FOUND,
        std::io::ErrorKind::PermissionDenied => ERR_ACCESS_DENIED,
        _ => ERR_PLATFORM,
    }
}

fn io_err(e: std::io::Error, ctx: &str) -> (i32, String) {
    (io_code(&e), format!("{ctx}: {e}"))
}

// ---------------------------------------------------------------------------
// Spec
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
pub struct DirSpec {
    pub path: String,
    pub max_files: Option<u64>,
}

/// A fully-validated `di_collect` spec (see `parse_spec`).
#[derive(Clone, Debug, PartialEq)]
pub struct Spec {
    pub output_zip: String,
    pub app_name: Option<String>,
    pub files: Vec<String>,
    pub directories: Vec<DirSpec>,
    pub file_info: Vec<String>,
    pub env: bool,
    pub extra_text: Vec<(String, String)>,
}

fn spec_string(v: &json::Value, key: &str) -> DiResult<String> {
    match v.as_str() {
        Some(s) if !s.is_empty() => Ok(s.to_string()),
        Some(_) => Err((ERR_INVALID_ARG, format!("\"{key}\" must not be empty"))),
        None => Err((
            ERR_INVALID_ARG,
            format!("\"{key}\" must be a string, got {}", v.type_name()),
        )),
    }
}

fn spec_string_array(v: &json::Value, key: &str) -> DiResult<Vec<String>> {
    let arr = v.as_array().ok_or((
        ERR_INVALID_ARG,
        format!(
            "\"{key}\" must be an array of strings, got {}",
            v.type_name()
        ),
    ))?;
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        out.push(spec_string(item, key)?);
    }
    Ok(out)
}

/// Parse and validate a `di_collect` spec JSON object:
///
///   {"output_zip": "C:/diag/bundle.zip", "app_name": "MyApp",
///    "files": ["C:/logs/app.log"],
///    "directories": [{"path": "C:/data", "max_files": 200}],
///    "file_info": ["C:/app/app.exe"],
///    "env": true,
///    "extra_text": {"notes.txt": "what happened"}}
///
/// `output_zip` is required and must be an absolute path.
/// Error discipline follows the family convention: malformed
/// JSON and unknown keys are `ERR_PARSE`; missing, empty, or
/// wrong-typed values are `ERR_INVALID_ARG`.
pub fn parse_spec(text: &str) -> DiResult<Spec> {
    let value =
        json::parse(text).map_err(|e| (ERR_PARSE, format!("spec is not valid JSON: {e}")))?;
    let obj = value
        .as_object()
        .ok_or((ERR_PARSE, "spec must be a JSON object".to_string()))?;
    for (key, _) in obj {
        if !matches!(
            key.as_str(),
            "output_zip"
                | "app_name"
                | "files"
                | "directories"
                | "file_info"
                | "env"
                | "extra_text"
        ) {
            return Err((ERR_PARSE, format!("unknown spec key \"{key}\"")));
        }
    }

    let output_zip = match value.get("output_zip") {
        None => {
            return Err((
                ERR_INVALID_ARG,
                "spec is missing required key \"output_zip\"".to_string(),
            ))
        }
        Some(v) => spec_string(v, "output_zip")?,
    };
    if !Path::new(&output_zip).is_absolute() {
        return Err((
            ERR_INVALID_ARG,
            format!("\"output_zip\" must be an absolute path, got \"{output_zip}\""),
        ));
    }

    let app_name = match value.get("app_name") {
        None => None,
        Some(v) => Some(spec_string(v, "app_name")?),
    };
    let files = match value.get("files") {
        None => Vec::new(),
        Some(v) => spec_string_array(v, "files")?,
    };
    let file_info = match value.get("file_info") {
        None => Vec::new(),
        Some(v) => spec_string_array(v, "file_info")?,
    };
    let directories = match value.get("directories") {
        None => Vec::new(),
        Some(v) => {
            let arr = v.as_array().ok_or((
                ERR_INVALID_ARG,
                format!("\"directories\" must be an array, got {}", v.type_name()),
            ))?;
            let mut out = Vec::with_capacity(arr.len());
            for item in arr {
                let dobj = item.as_object().ok_or((
                    ERR_INVALID_ARG,
                    format!(
                        "\"directories\" entries must be objects, got {}",
                        item.type_name()
                    ),
                ))?;
                for (key, _) in dobj {
                    if !matches!(key.as_str(), "path" | "max_files") {
                        return Err((ERR_PARSE, format!("unknown directories key \"{key}\"")));
                    }
                }
                let path = match item.get("path") {
                    None => {
                        return Err((
                            ERR_INVALID_ARG,
                            "a \"directories\" entry is missing required key \"path\"".to_string(),
                        ))
                    }
                    Some(pv) => spec_string(pv, "path")?,
                };
                let max_files = match item.get("max_files") {
                    None => None,
                    Some(mv) => match mv.as_i64() {
                        Some(n) if n >= 0 => Some(n as u64),
                        _ => {
                            return Err((
                                ERR_INVALID_ARG,
                                format!(
                                    "\"max_files\" must be a non-negative integer, got {}",
                                    mv.type_name()
                                ),
                            ))
                        }
                    },
                };
                out.push(DirSpec { path, max_files });
            }
            out
        }
    };
    let env = match value.get("env") {
        None => false,
        Some(v) => v.as_bool().ok_or((
            ERR_INVALID_ARG,
            format!("\"env\" must be a boolean, got {}", v.type_name()),
        ))?,
    };
    let extra_text = match value.get("extra_text") {
        None => Vec::new(),
        Some(v) => {
            let pairs = v.as_object().ok_or((
                ERR_INVALID_ARG,
                format!(
                    "\"extra_text\" must be an object of string to string, got {}",
                    v.type_name()
                ),
            ))?;
            let mut out = Vec::with_capacity(pairs.len());
            for (k, val) in pairs {
                let s = val.as_str().ok_or((
                    ERR_INVALID_ARG,
                    format!("\"extra_text\" value for \"{k}\" must be a string"),
                ))?;
                out.push((k.clone(), s.to_string()));
            }
            out
        }
    };

    Ok(Spec {
        output_zip,
        app_name,
        files,
        directories,
        file_info,
        env,
        extra_text,
    })
}

// ---------------------------------------------------------------------------
// Entry names
// ---------------------------------------------------------------------------

/// Derive a zip entry name from a canonical absolute path:
/// the path's normal components joined with `/` (root and
/// drive prefix dropped). A canonical path has no `..` or
/// `.` components, so the derived name is traversal-safe by
/// construction.
pub fn entry_name_for(canonical: &Path) -> String {
    let mut parts: Vec<String> = Vec::new();
    for c in canonical.components() {
        if let Component::Normal(os) = c {
            parts.push(os.to_string_lossy().into_owned());
        }
    }
    if parts.is_empty() {
        "file".to_string()
    } else {
        parts.join("/")
    }
}

/// Validate a caller-chosen entry name (`extra_text` keys).
/// The rules are the bundle's safety contract: relative,
/// `/`-separated, no `..`/`.`/empty components, no `\`, no
/// drive prefix, no control characters, and never the
/// reserved manifest name.
pub fn validate_entry_name(name: &str) -> DiResult<()> {
    let bad = |why: &str| -> (i32, String) {
        (
            ERR_INVALID_ARG,
            format!("invalid entry name \"{name}\": {why}"),
        )
    };
    if name.is_empty() {
        return Err(bad("name is empty"));
    }
    if name == MANIFEST_NAME {
        return Err(bad("\"manifest.json\" is reserved for the bundle manifest"));
    }
    if name.starts_with('/') || name.starts_with('\\') {
        return Err(bad("absolute paths are not allowed"));
    }
    if name.len() >= 2 && name.as_bytes()[1] == b':' {
        return Err(bad("drive prefixes are not allowed"));
    }
    if name.contains('\\') {
        return Err(bad("use '/' as the separator, not '\\'"));
    }
    if name.chars().any(|c| (c as u32) < 0x20) {
        return Err(bad("control characters are not allowed"));
    }
    for comp in name.split('/') {
        match comp {
            "" => {
                return Err(bad(
                    "empty path component (leading, trailing or doubled '/')",
                ))
            }
            "." => return Err(bad("'.' components are not allowed")),
            ".." => return Err(bad("'..' components are not allowed")),
            _ => {}
        }
    }
    Ok(())
}

/// Claim `desired` in the taken set, suffixing ` (2)`,
/// ` (3)`, … before the extension when the name is already
/// used — derived names must never lose a file to a
/// collision, and must never collide with each other.
fn claim_name(taken: &mut HashSet<String>, desired: String) -> String {
    if taken.insert(desired.clone()) {
        return desired;
    }
    // Split the final component into stem + extension.
    let (dir, file) = match desired.rfind('/') {
        Some(i) => (&desired[..=i], &desired[i + 1..]),
        None => ("", desired.as_str()),
    };
    let (stem, ext) = match file.rfind('.') {
        Some(i) if i > 0 => (&file[..i], &file[i..]),
        _ => (file, ""),
    };
    let mut n = 2;
    loop {
        let candidate = format!("{dir}{stem} ({n}){ext}");
        if taken.insert(candidate.clone()) {
            return candidate;
        }
        n += 1;
    }
}

// ---------------------------------------------------------------------------
// Planning
// ---------------------------------------------------------------------------

struct PlannedFile {
    source: PathBuf, // canonical
    entry_name: String,
}

struct Plan {
    output_path: PathBuf,
    files: Vec<PlannedFile>,
    extras: Vec<(String, String)>,
}

fn canonical_input(path: &str, what: &str) -> DiResult<PathBuf> {
    std::fs::canonicalize(path).map_err(|e| {
        let code = if e.kind() == std::io::ErrorKind::NotFound {
            ERR_NOT_FOUND
        } else {
            io_code(&e)
        };
        (code, format!("{what} \"{path}\": {e}"))
    })
}

fn plan(spec: &Spec) -> DiResult<Plan> {
    // Output: parent must already exist (collect never
    // creates directories silently), and the bundle may not
    // contain itself.
    let output_path = PathBuf::from(&spec.output_zip);
    let parent = output_path
        .parent()
        .ok_or((
            ERR_INVALID_ARG,
            format!(
                "\"output_zip\" has no parent directory: \"{}\"",
                spec.output_zip
            ),
        ))?
        .to_path_buf();
    let parent_meta = std::fs::metadata(&parent).map_err(|e| {
        (
            ERR_NOT_FOUND,
            format!("output directory \"{}\": {e}", parent.display()),
        )
    })?;
    if !parent_meta.is_dir() {
        return Err((
            ERR_INVALID_ARG,
            format!(
                "output path's parent is not a directory: \"{}\"",
                parent.display()
            ),
        ));
    }
    let canonical_output = std::fs::canonicalize(&parent)
        .map_err(|e| io_err(e, "cannot resolve the output directory"))?
        .join(output_path.file_name().ok_or((
            ERR_INVALID_ARG,
            format!("\"output_zip\" has no file name: \"{}\"", spec.output_zip),
        ))?);

    let mut taken: HashSet<String> = HashSet::new();
    taken.insert(MANIFEST_NAME.to_string());
    let mut total: u64 = 0;
    let mut files = Vec::with_capacity(spec.files.len());
    for raw in &spec.files {
        let source = canonical_input(raw, "input file")?;
        if source == canonical_output {
            return Err((
                ERR_INVALID_ARG,
                format!("input file \"{raw}\" is the output bundle itself"),
            ));
        }
        let meta = std::fs::metadata(&source)
            .map_err(|e| io_err(e, &format!("cannot stat input file \"{raw}\"")))?;
        if meta.is_dir() {
            return Err((
                ERR_INVALID_ARG,
                format!(
                    "input file \"{raw}\" is a directory — list directories via \"directories\", not \"files\""
                ),
            ));
        }
        let size = meta.len();
        if size > MAX_FILE_BYTES {
            return Err((
                ERR_TOO_LARGE,
                format!(
                    "file \"{raw}\" is {size} bytes, over the per-file cap of {MAX_FILE_BYTES} bytes"
                ),
            ));
        }
        total = total.saturating_add(size);
        if total > MAX_TOTAL_BYTES {
            return Err((
                ERR_TOO_LARGE,
                format!(
                    "adding file \"{raw}\" takes the bundle over the total cap of {MAX_TOTAL_BYTES} bytes"
                ),
            ));
        }
        let entry_name = claim_name(&mut taken, entry_name_for(&source));
        files.push(PlannedFile { source, entry_name });
    }

    let mut extras = Vec::with_capacity(spec.extra_text.len());
    for (name, content) in &spec.extra_text {
        validate_entry_name(name)?;
        // Extras are caller-named: a clash is the caller's to
        // fix, so it is an error, not a silent rename.
        if taken.contains(name) {
            return Err((
                ERR_INVALID_ARG,
                format!("entry name \"{name}\" is already used by another bundle entry"),
            ));
        }
        let size = content.len() as u64;
        if size > MAX_FILE_BYTES {
            return Err((
                ERR_TOO_LARGE,
                format!(
                    "extra_text entry \"{name}\" is {size} bytes, over the per-file cap of {MAX_FILE_BYTES} bytes"
                ),
            ));
        }
        total = total.saturating_add(size);
        if total > MAX_TOTAL_BYTES {
            return Err((
                ERR_TOO_LARGE,
                format!(
                    "adding extra_text entry \"{name}\" takes the bundle over the total cap of {MAX_TOTAL_BYTES} bytes"
                ),
            ));
        }
        taken.insert(name.clone());
        extras.push((name.clone(), content.clone()));
    }

    Ok(Plan {
        output_path,
        files,
        extras,
    })
}

// ---------------------------------------------------------------------------
// File info + directory listings
// ---------------------------------------------------------------------------

pub struct FileInfo {
    pub path: String, // as given in the spec
    pub size: u64,
    pub sha256: String,
    pub version: Option<Vec<(String, String)>>,
}

fn sha256_file(path: &Path, display: &str) -> DiResult<(u64, String)> {
    use std::io::Read;
    let mut f =
        std::fs::File::open(path).map_err(|e| io_err(e, &format!("cannot open \"{display}\"")))?;
    let mut h = hash::Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    let mut size: u64 = 0;
    loop {
        let n = f
            .read(&mut buf)
            .map_err(|e| io_err(e, &format!("cannot read \"{display}\"")))?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
        size += n as u64;
    }
    Ok((size, h.finalize_hex()))
}

fn gather_file_info(spec: &Spec) -> DiResult<Vec<FileInfo>> {
    let mut out = Vec::with_capacity(spec.file_info.len());
    for raw in &spec.file_info {
        let canonical = canonical_input(raw, "file_info path")?;
        let meta = std::fs::metadata(&canonical)
            .map_err(|e| io_err(e, &format!("cannot stat file_info path \"{raw}\"")))?;
        if meta.is_dir() {
            return Err((
                ERR_INVALID_ARG,
                format!("file_info path \"{raw}\" is a directory"),
            ));
        }
        let (size, sha) = sha256_file(&canonical, raw)?;
        let version = platform::version_strings(&canonical)?;
        out.push(FileInfo {
            path: raw.clone(),
            size,
            sha256: sha,
            version,
        });
    }
    Ok(out)
}

pub struct DirListing {
    pub path: String,                // as given in the spec
    pub entries: Vec<(String, u64)>, // (root-relative name, size), sorted
    pub truncated: bool,
}

/// Walk `root` recursively collecting file names + sizes
/// (never contents). Symlinks are listed as entries and
/// never followed, so a link cycle cannot loop the walk.
/// Unreadable subdirectories are skipped (documented); an
/// unreadable `root` itself is an error. Stops as soon as
/// one entry past `cap` is seen and reports `truncated`.
pub fn list_directory(root: &Path, cap: usize) -> DiResult<(Vec<(String, u64)>, bool)> {
    let mut entries: Vec<(String, u64)> = Vec::new();
    let mut stack: Vec<PathBuf> = vec![root.to_path_buf()];
    let mut truncated = false;
    'walk: while let Some(dir) = stack.pop() {
        let rd = match std::fs::read_dir(&dir) {
            Ok(rd) => rd,
            Err(e) => {
                if dir == root {
                    return Err(io_err(
                        e,
                        &format!("cannot list directory \"{}\"", root.display()),
                    ));
                }
                continue; // unreadable subdirectory: skipped, documented
            }
        };
        for entry in rd {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };
            let ftype = match entry.file_type() {
                Ok(t) => t,
                Err(_) => continue,
            };
            let path = entry.path();
            if ftype.is_dir() {
                stack.push(path);
                continue;
            }
            // Files and symlinks (never followed).
            let size = match std::fs::symlink_metadata(&path) {
                Ok(m) => m.len(),
                Err(_) => continue,
            };
            if entries.len() >= cap {
                truncated = true;
                break 'walk;
            }
            let rel = match path.strip_prefix(root) {
                Ok(r) => r
                    .components()
                    .filter_map(|c| match c {
                        Component::Normal(os) => Some(os.to_string_lossy().into_owned()),
                        _ => None,
                    })
                    .collect::<Vec<_>>()
                    .join("/"),
                Err(_) => continue,
            };
            if !rel.is_empty() {
                entries.push((rel, size));
            }
        }
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    Ok((entries, truncated))
}

fn gather_directories(spec: &Spec) -> DiResult<Vec<DirListing>> {
    let mut out = Vec::with_capacity(spec.directories.len());
    for d in &spec.directories {
        let canonical = canonical_input(&d.path, "directory")?;
        let meta = std::fs::metadata(&canonical)
            .map_err(|e| io_err(e, &format!("cannot stat directory \"{}\"", d.path)))?;
        if !meta.is_dir() {
            return Err((
                ERR_INVALID_ARG,
                format!("directory \"{}\" is not a directory", d.path),
            ));
        }
        let cap = d
            .max_files
            .map(|m| m as usize)
            .unwrap_or(MAX_DIR_ENTRIES)
            .min(MAX_DIR_ENTRIES);
        let (entries, truncated) = list_directory(&canonical, cap)?;
        out.push(DirListing {
            path: d.path.clone(),
            entries,
            truncated,
        });
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Time
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct UtcParts {
    pub year: i64,
    pub month: u32,
    pub day: u32,
    pub hour: u32,
    pub min: u32,
    pub sec: u32,
}

/// Civil date from days since the Unix epoch (Howard
/// Hinnant's algorithm — exact for the whole DOS-date range
/// and far beyond).
pub fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m as u32, d as u32)
}

pub fn utc_parts_from_unix(secs: u64) -> UtcParts {
    let days = (secs / 86_400) as i64;
    let tod = secs % 86_400;
    let (year, month, day) = civil_from_days(days);
    UtcParts {
        year,
        month,
        day,
        hour: (tod / 3600) as u32,
        min: ((tod % 3600) / 60) as u32,
        sec: (tod % 60) as u32,
    }
}

pub fn utc_now() -> UtcParts {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    utc_parts_from_unix(secs)
}

impl UtcParts {
    pub fn iso8601(&self) -> String {
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            self.year, self.month, self.day, self.hour, self.min, self.sec
        )
    }

    /// DOS (date, time) pair for ZIP headers, clamped to the
    /// representable 1980–2107 range.
    pub fn dos(&self) -> (u16, u16) {
        let year = self.year.clamp(1980, 2107);
        let date = (((year - 1980) as u16) << 9) | ((self.month as u16) << 5) | self.day as u16;
        let time = ((self.hour as u16) << 11) | ((self.min as u16) << 5) | ((self.sec as u16) / 2);
        (date, time)
    }
}

// ---------------------------------------------------------------------------
// Manifest + collect
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct CollectResult {
    pub zip: String,
    pub entries: usize,
    pub bytes: u64,
}

impl CollectResult {
    pub fn to_json(&self) -> String {
        format!(
            "{{\"zip\":\"{}\",\"entries\":{},\"bytes\":{}}}",
            json_escape(&self.zip),
            self.entries,
            self.bytes
        )
    }
}

fn manifest_json(
    app_name: &Option<String>,
    created: &UtcParts,
    entries: &[zip::WrittenEntry],
    file_info: &[FileInfo],
    directories: &[DirListing],
    env: &Option<(String, String, Option<String>)>,
) -> String {
    let mut s = String::with_capacity(1024);
    s.push_str("{\"kit\":\"DiagKit\",\"kit_version\":\"");
    s.push_str(VERSION);
    s.push_str("\",\"created_utc\":\"");
    s.push_str(&created.iso8601());
    s.push_str("\",\"app_name\":");
    match app_name {
        Some(a) => {
            s.push('"');
            s.push_str(&json_escape(a));
            s.push('"');
        }
        None => s.push_str("null"),
    }
    s.push_str(",\"entries\":[");
    for (i, e) in entries.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str(&format!(
            "{{\"name\":\"{}\",\"size\":{},\"sha256\":\"{}\"}}",
            json_escape(&e.name),
            e.size,
            e.sha256
        ));
    }
    s.push_str("],\"file_info\":[");
    for (i, fi) in file_info.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str(&format!(
            "{{\"path\":\"{}\",\"size\":{},\"sha256\":\"",
            json_escape(&fi.path),
            fi.size
        ));
        s.push_str(&fi.sha256);
        s.push_str("\",\"version\":");
        match &fi.version {
            Some(pairs) => {
                s.push('{');
                for (j, (k, v)) in pairs.iter().enumerate() {
                    if j > 0 {
                        s.push(',');
                    }
                    s.push_str(&format!("\"{}\":\"{}\"", json_escape(k), json_escape(v)));
                }
                s.push('}');
            }
            None => s.push_str("null"),
        }
        s.push('}');
    }
    s.push_str("],\"directories\":[");
    for (i, d) in directories.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str(&format!(
            "{{\"path\":\"{}\",\"count\":{},\"truncated\":{},\"entries\":[",
            json_escape(&d.path),
            d.entries.len(),
            d.truncated
        ));
        for (j, (rel, size)) in d.entries.iter().enumerate() {
            if j > 0 {
                s.push(',');
            }
            s.push_str(&format!(
                "{{\"path\":\"{}\",\"size\":{}}}",
                json_escape(rel),
                size
            ));
        }
        s.push_str("]}");
    }
    s.push_str("],\"env\":");
    match env {
        Some((os, arch, computer)) => {
            s.push_str(&format!(
                "{{\"os\":\"{}\",\"arch\":\"{}\",\"computer_name\":",
                json_escape(os),
                json_escape(arch)
            ));
            match computer {
                Some(c) => {
                    s.push('"');
                    s.push_str(&json_escape(c));
                    s.push('"');
                }
                None => s.push_str("null"),
            }
            s.push('}');
        }
        None => s.push_str("null"),
    }
    s.push('}');
    s
}

/// Run a collection from a spec JSON string: validate, plan
/// (caps checked from sizes before anything is read), gather
/// the side information, then write the bundle to a temp
/// file beside the output and rename it into place — a
/// failed collection never leaves a partial zip at
/// `output_zip`.
pub fn collect(spec_json: &str) -> DiResult<CollectResult> {
    let spec = parse_spec(spec_json)?;
    let plan = plan(&spec)?;
    let file_info = gather_file_info(&spec)?;
    let directories = gather_directories(&spec)?;
    let env = if spec.env {
        Some((
            std::env::consts::OS.to_string(),
            std::env::consts::ARCH.to_string(),
            std::env::var("COMPUTERNAME").ok().filter(|s| !s.is_empty()),
        ))
    } else {
        None
    };
    let created = utc_now();
    let (dos_date, dos_time) = created.dos();

    // Write to a temp sibling, rename at the end.
    let parent = plan.output_path.parent().ok_or((
        ERR_INVALID_ARG,
        "output path has no parent directory".to_string(),
    ))?;
    let file_name = plan
        .output_path
        .file_name()
        .ok_or((ERR_INVALID_ARG, "output path has no file name".to_string()))?
        .to_string_lossy()
        .into_owned();
    let temp_path = parent.join(format!(".{file_name}.tmp-{}", std::process::id()));
    let _ = std::fs::remove_file(&temp_path);

    let write_outcome = (|| -> DiResult<(usize, u64)> {
        let out_file = std::fs::File::create(&temp_path)
            .map_err(|e| io_err(e, &format!("cannot create \"{}\"", spec.output_zip)))?;
        let mut zw = zip::ZipWriter::new(out_file, dos_date, dos_time);
        let mut written: Vec<zip::WrittenEntry> = Vec::new();
        let mut total: u64 = 0;
        for pf in &plan.files {
            let f = std::fs::File::open(&pf.source).map_err(|e| {
                io_err(
                    e,
                    &format!("cannot open input file \"{}\"", pf.source.display()),
                )
            })?;
            let entry = zw.add_reader(&pf.entry_name, f).map_err(|e| {
                io_err(
                    e,
                    &format!("cannot write bundle entry \"{}\"", pf.entry_name),
                )
            })?;
            if entry.size > MAX_FILE_BYTES {
                return Err((
                    ERR_TOO_LARGE,
                    format!(
                        "file \"{}\" grew past the per-file cap of {MAX_FILE_BYTES} bytes while collecting",
                        pf.source.display()
                    ),
                ));
            }
            total = total.saturating_add(entry.size);
            if total > MAX_TOTAL_BYTES {
                return Err((
                    ERR_TOO_LARGE,
                    format!(
                        "bundle grew past the total cap of {MAX_TOTAL_BYTES} bytes at file \"{}\"",
                        pf.source.display()
                    ),
                ));
            }
            written.push(entry);
        }
        for (name, content) in &plan.extras {
            let entry = zw
                .add_bytes(name, content.as_bytes())
                .map_err(|e| io_err(e, &format!("cannot write bundle entry \"{name}\"")))?;
            total = total.saturating_add(entry.size);
            written.push(entry);
        }
        let manifest = manifest_json(
            &spec.app_name,
            &created,
            &written,
            &file_info,
            &directories,
            &env,
        );
        if total.saturating_add(manifest.len() as u64) > MAX_TOTAL_BYTES {
            return Err((
                ERR_TOO_LARGE,
                format!("bundle exceeds the total cap of {MAX_TOTAL_BYTES} bytes"),
            ));
        }
        zw.add_bytes(MANIFEST_NAME, manifest.as_bytes())
            .map_err(|e| io_err(e, "cannot write the bundle manifest"))?;
        zw.finish()
            .map_err(|e| io_err(e, "cannot finish the bundle"))
    })();

    match write_outcome {
        Ok((entries, bytes)) => {
            std::fs::rename(&temp_path, &plan.output_path).map_err(|e| {
                let _ = std::fs::remove_file(&temp_path);
                io_err(
                    e,
                    &format!(
                        "cannot move the bundle into place at \"{}\"",
                        spec.output_zip
                    ),
                )
            })?;
            Ok(CollectResult {
                zip: spec.output_zip.clone(),
                entries,
                bytes,
            })
        }
        Err(err) => {
            let _ = std::fs::remove_file(&temp_path);
            Err(err)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_json() {
        assert_eq!(json_escape("a\"b\\c\nd"), "a\\\"b\\\\c\\nd");
    }

    #[test]
    fn civil_dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(11016), (2000, 2, 29)); // leap day
        assert_eq!(civil_from_days(11017), (2000, 3, 1));
        let p = utc_parts_from_unix(951_782_400); // 2000-02-29T00:00:00Z
        assert_eq!(
            (p.year, p.month, p.day, p.hour, p.min, p.sec),
            (2000, 2, 29, 0, 0, 0)
        );
        assert_eq!(p.iso8601(), "2000-02-29T00:00:00Z");
        // DOS clamps the year at 1980.
        let (date, _) = utc_parts_from_unix(0).dos();
        assert_eq!(date >> 9, 0); // 1980 - 1980
    }

    #[test]
    fn spec_parse_rules() {
        let ok = parse_spec(
            r#"{"output_zip":"/tmp/b.zip","app_name":"A","files":["/a.log"],"env":true,
                "directories":[{"path":"/d","max_files":10}],"extra_text":{"n.txt":"hi"}}"#,
        )
        .unwrap();
        assert_eq!(ok.app_name.as_deref(), Some("A"));
        assert_eq!(ok.directories[0].max_files, Some(10));
        assert_eq!(ok.extra_text, vec![("n.txt".to_string(), "hi".to_string())]);

        assert_eq!(parse_spec(r#"{"output_zip":"#).unwrap_err().0, ERR_PARSE);
        assert_eq!(
            parse_spec(r#"{"output_zip":"/tmp/b.zip","bogus":1}"#)
                .unwrap_err()
                .0,
            ERR_PARSE // unknown key
        );
        assert_eq!(
            parse_spec(r#"{"output_zip":"/tmp/b.zip","output_zip":"/tmp/c.zip"}"#)
                .unwrap_err()
                .0,
            ERR_PARSE // duplicate key
        );
        assert_eq!(
            parse_spec(r#"{}"#).unwrap_err().0,
            ERR_INVALID_ARG // missing output_zip
        );
        assert_eq!(
            parse_spec(r#"{"output_zip":"relative.zip"}"#)
                .unwrap_err()
                .0,
            ERR_INVALID_ARG // not absolute
        );
        assert_eq!(
            parse_spec(r#"{"output_zip":"/tmp/b.zip","env":"yes"}"#)
                .unwrap_err()
                .0,
            ERR_INVALID_ARG // env wrong type
        );
        assert_eq!(
            parse_spec(r#"{"output_zip":"/tmp/b.zip","directories":[{"max_files":1}]}"#)
                .unwrap_err()
                .0,
            ERR_INVALID_ARG // directory without path
        );
        assert_eq!(
            parse_spec(
                r#"{"output_zip":"/tmp/b.zip","directories":[{"path":"/d","max_files":-1}]}"#
            )
            .unwrap_err()
            .0,
            ERR_INVALID_ARG // negative max_files
        );
    }

    #[test]
    fn entry_name_rules() {
        assert_eq!(
            entry_name_for(Path::new("/var/log/app.log")),
            "var/log/app.log"
        );
        assert!(validate_entry_name("notes.txt").is_ok());
        assert!(validate_entry_name("a/b/c.txt").is_ok());
        for bad in [
            "../evil.txt",
            "a/../b.txt",
            "/abs.txt",
            "a\\b.txt",
            "C:/x.txt",
            "manifest.json",
            "a//b.txt",
            "trail/",
            "./x.txt",
            "",
        ] {
            assert_eq!(
                validate_entry_name(bad).unwrap_err().0,
                ERR_INVALID_ARG,
                "name {bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn claim_name_suffixes() {
        let mut taken = HashSet::new();
        taken.insert(MANIFEST_NAME.to_string());
        assert_eq!(claim_name(&mut taken, "a/log.txt".into()), "a/log.txt");
        assert_eq!(claim_name(&mut taken, "a/log.txt".into()), "a/log (2).txt");
        assert_eq!(claim_name(&mut taken, "a/log.txt".into()), "a/log (3).txt");
        assert_eq!(
            claim_name(&mut taken, "manifest.json".into()),
            "manifest (2).json"
        );
        assert_eq!(claim_name(&mut taken, "noext".into()), "noext");
        assert_eq!(claim_name(&mut taken, "noext".into()), "noext (2)");
    }

    // -- Collection against real files -------------------------------

    use std::sync::atomic::{AtomicUsize, Ordering};

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    /// A fresh temp directory per test; removed on drop.
    struct TestDir(PathBuf);
    impl TestDir {
        fn new(tag: &str) -> TestDir {
            let n = COUNTER.fetch_add(1, Ordering::SeqCst);
            let d =
                std::env::temp_dir().join(format!("diagkit-test-{}-{tag}-{n}", std::process::id()));
            std::fs::create_dir_all(&d).unwrap();
            TestDir(d)
        }
        fn path(&self) -> &Path {
            &self.0
        }
        fn write(&self, rel: &str, data: &[u8]) -> PathBuf {
            let p = self.0.join(rel);
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(&p, data).unwrap();
            p
        }
        fn sparse(&self, rel: &str, len: u64) -> PathBuf {
            let p = self.0.join(rel);
            let f = std::fs::File::create(&p).unwrap();
            f.set_len(len).unwrap();
            p
        }
        fn spec_json(&self, extra: &str) -> String {
            let out = self.0.join("bundle.zip");
            if extra.is_empty() {
                format!(
                    "{{\"output_zip\":\"{}\"}}",
                    json_escape(&out.to_string_lossy())
                )
            } else {
                format!(
                    "{{\"output_zip\":\"{}\",{extra}}}",
                    json_escape(&out.to_string_lossy())
                )
            }
        }
    }
    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn read_zip(td: &TestDir) -> Vec<u8> {
        std::fs::read(td.path().join("bundle.zip")).unwrap()
    }

    fn manifest_of(zip: &[u8]) -> json::Value {
        let central = zip::read_central_directory(zip).unwrap();
        let m = central
            .iter()
            .find(|e| e.name == MANIFEST_NAME)
            .expect("bundle must contain manifest.json");
        let data = zip::extract(zip, m).unwrap();
        assert_eq!(hash::crc32(&data), m.crc32);
        json::parse(std::str::from_utf8(&data).unwrap()).unwrap()
    }

    #[test]
    fn collect_happy_path_and_manifest_match() {
        let td = TestDir::new("happy");
        let log = td.write("logs/app.log", b"line one\nline two\n");
        let dump = td.write("crash.dmp", &[7u8; 100]);
        let spec = td.spec_json(&format!(
            "\"app_name\":\"TestApp\",\"files\":[\"{}\",\"{}\"],\
             \"extra_text\":{{\"notes/readme.txt\":\"bundle notes\"}},\
             \"file_info\":[\"{}\"],\"directories\":[{{\"path\":\"{}\"}}],\"env\":true",
            json_escape(&log.to_string_lossy()),
            json_escape(&dump.to_string_lossy()),
            json_escape(&log.to_string_lossy()),
            json_escape(&td.path().to_string_lossy()),
        ));
        let result = collect(&spec).unwrap();
        assert_eq!(result.entries, 4); // 2 files + 1 extra + manifest
        let bytes = read_zip(&td);
        assert_eq!(result.bytes, bytes.len() as u64);
        assert!(result.zip.ends_with("bundle.zip"));

        // The archive reads back by the standard semantics:
        // central directory, extraction, CRC verification.
        let central = zip::read_central_directory(&bytes).unwrap();
        let names: Vec<&str> = central.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names.len(), 4);
        assert_eq!(names[3], MANIFEST_NAME);
        for e in &central {
            let data = zip::extract(&bytes, e).unwrap();
            assert_eq!(hash::crc32(&data), e.crc32, "CRC failed for {}", e.name);
        }
        let log_entry = central
            .iter()
            .find(|e| e.name.ends_with("logs/app.log"))
            .unwrap();
        assert_eq!(
            zip::extract(&bytes, log_entry).unwrap(),
            b"line one\nline two\n"
        );
        let notes = central
            .iter()
            .find(|e| e.name == "notes/readme.txt")
            .unwrap();
        assert_eq!(zip::extract(&bytes, notes).unwrap(), b"bundle notes");

        // The manifest describes exactly what was collected.
        let m = manifest_of(&bytes);
        assert_eq!(m.get("kit").unwrap().as_str(), Some("DiagKit"));
        assert_eq!(m.get("kit_version").unwrap().as_str(), Some("0.1.0"));
        assert_eq!(m.get("app_name").unwrap().as_str(), Some("TestApp"));
        let created = m.get("created_utc").unwrap().as_str().unwrap();
        assert_eq!(created.len(), 20);
        assert!(created.ends_with('Z'));
        let entries = m.get("entries").unwrap().as_array().unwrap();
        assert_eq!(entries.len(), 3); // manifest does not list itself
        let log_m = entries
            .iter()
            .find(|e| {
                e.get("name")
                    .unwrap()
                    .as_str()
                    .unwrap()
                    .ends_with("logs/app.log")
            })
            .unwrap();
        assert_eq!(log_m.get("size").unwrap().as_i64(), Some(18));
        assert_eq!(
            log_m.get("sha256").unwrap().as_str(),
            Some(hash::sha256_hex(b"line one\nline two\n").as_str())
        );
        let fi = m.get("file_info").unwrap().as_array().unwrap();
        assert_eq!(fi.len(), 1);
        assert_eq!(fi[0].get("size").unwrap().as_i64(), Some(18));
        assert_eq!(
            fi[0].get("sha256").unwrap().as_str(),
            Some(hash::sha256_hex(b"line one\nline two\n").as_str())
        );
        #[cfg(not(windows))]
        assert_eq!(fi[0].get("version").unwrap(), &json::Value::Null);
        let dirs = m.get("directories").unwrap().as_array().unwrap();
        assert_eq!(dirs.len(), 1);
        let listed = dirs[0].get("entries").unwrap().as_array().unwrap();
        let listed_names: Vec<&str> = listed
            .iter()
            .map(|e| e.get("path").unwrap().as_str().unwrap())
            .collect();
        assert!(listed_names.contains(&"logs/app.log"));
        assert!(listed_names.contains(&"crash.dmp"));
        assert_eq!(dirs[0].get("truncated").unwrap().as_bool(), Some(false));
        let env = m.get("env").unwrap();
        assert_eq!(env.get("os").unwrap().as_str(), Some(std::env::consts::OS));
        assert_eq!(
            env.get("arch").unwrap().as_str(),
            Some(std::env::consts::ARCH)
        );
    }

    #[test]
    fn collect_minimal_spec_makes_manifest_only_bundle() {
        let td = TestDir::new("minimal");
        let result = collect(&td.spec_json("")).unwrap();
        assert_eq!(result.entries, 1);
        let bytes = read_zip(&td);
        let central = zip::read_central_directory(&bytes).unwrap();
        assert_eq!(central.len(), 1);
        assert_eq!(central[0].name, MANIFEST_NAME);
        let m = manifest_of(&bytes);
        assert_eq!(m.get("app_name").unwrap(), &json::Value::Null);
        assert_eq!(m.get("env").unwrap(), &json::Value::Null);
        assert_eq!(m.get("entries").unwrap().as_array().unwrap().len(), 0);
    }

    #[test]
    fn collect_missing_inputs_are_clean_errors() {
        let td = TestDir::new("missing");
        let missing = td.path().join("nope.log");
        let missing = json_escape(&missing.to_string_lossy());

        let err = collect(&td.spec_json(&format!("\"files\":[\"{missing}\"]"))).unwrap_err();
        assert_eq!(err.0, ERR_NOT_FOUND);
        assert!(
            err.1.contains("nope.log"),
            "error must name the file: {}",
            err.1
        );

        let err = collect(&td.spec_json(&format!("\"file_info\":[\"{missing}\"]"))).unwrap_err();
        assert_eq!(err.0, ERR_NOT_FOUND);

        let err = collect(&td.spec_json(&format!("\"directories\":[{{\"path\":\"{missing}\"}}]")))
            .unwrap_err();
        assert_eq!(err.0, ERR_NOT_FOUND);

        // Nothing was written anywhere along the way.
        assert!(!td.path().join("bundle.zip").exists());
    }

    #[test]
    fn collect_rejects_traversal_in_extra_text() {
        let td = TestDir::new("traversal");
        for bad in ["../evil.txt", "a/../../b.txt", "/abs.txt", "manifest.json"] {
            let spec = td.spec_json(&format!("\"extra_text\":{{\"{bad}\":\"x\"}}"));
            let err = collect(&spec).unwrap_err();
            assert_eq!(err.0, ERR_INVALID_ARG, "name {bad}");
            assert!(err.1.contains(bad), "error must name the entry: {}", err.1);
            assert!(!td.path().join("bundle.zip").exists());
        }
    }

    #[test]
    fn collect_enforces_the_caps() {
        let td = TestDir::new("caps");
        // Per-file cap: 64 MiB + 1, sparse (plan rejects from
        // the size alone, before a byte is read).
        let big = td.sparse("big.bin", MAX_FILE_BYTES + 1);
        let spec = td.spec_json(&format!(
            "\"files\":[\"{}\"]",
            json_escape(&big.to_string_lossy())
        ));
        let err = collect(&spec).unwrap_err();
        assert_eq!(err.0, ERR_TOO_LARGE);
        assert!(
            err.1.contains("big.bin"),
            "error must name the file: {}",
            err.1
        );
        assert!(!td.path().join("bundle.zip").exists());

        // Total cap: five 60 MiB files pass the per-file cap
        // individually but sum past 256 MiB.
        let mut names = Vec::new();
        for i in 0..5 {
            let p = td.sparse(&format!("part{i}.bin"), 60 * 1024 * 1024);
            names.push(format!("\"{}\"", json_escape(&p.to_string_lossy())));
        }
        let spec = td.spec_json(&format!("\"files\":[{}]", names.join(",")));
        let err = collect(&spec).unwrap_err();
        assert_eq!(err.0, ERR_TOO_LARGE);
        assert!(!td.path().join("bundle.zip").exists());
    }

    #[test]
    fn collect_same_file_twice_gets_distinct_entries() {
        let td = TestDir::new("twice");
        let f = td.write("a/log.txt", b"data");
        let p = json_escape(&f.to_string_lossy());
        let spec = td.spec_json(&format!("\"files\":[\"{p}\",\"{p}\"]"));
        let result = collect(&spec).unwrap();
        assert_eq!(result.entries, 3);
        let bytes = read_zip(&td);
        let central = zip::read_central_directory(&bytes).unwrap();
        assert!(
            central[0].name.ends_with("a/log.txt"),
            "{}",
            central[0].name
        );
        assert!(
            central[1].name.ends_with("a/log (2).txt"),
            "{}",
            central[1].name
        );
    }

    #[test]
    fn directory_listing_cap_and_truncation() {
        let td = TestDir::new("listing");
        let root = td.path().join("root");
        std::fs::create_dir_all(root.join("sub")).unwrap();
        for i in 0..4 {
            td.write(&format!("root/f{i}.txt"), b"x");
        }
        td.write("root/sub/deep.txt", b"yy");
        // Full listing: 5 files, sorted, with sizes.
        let (entries, truncated) = list_directory(&root, 5000).unwrap();
        assert!(!truncated);
        assert_eq!(entries.len(), 5);
        assert_eq!(entries[0].0, "f0.txt");
        assert_eq!(entries[4].0, "sub/deep.txt");
        assert_eq!(entries[4].1, 2);
        // Capped: exactly cap entries and the truncated flag.
        let (entries, truncated) = list_directory(&root, 3).unwrap();
        assert!(truncated);
        assert_eq!(entries.len(), 3);
    }

    #[test]
    fn collect_directory_max_files_clamps_and_reports() {
        let td = TestDir::new("dirmax");
        for i in 0..6 {
            td.write(&format!("data/f{i}.txt"), b"x");
        }
        let root = td.path().join("data");
        let spec = td.spec_json(&format!(
            "\"directories\":[{{\"path\":\"{}\",\"max_files\":2}}]",
            json_escape(&root.to_string_lossy())
        ));
        collect(&spec).unwrap();
        let m = manifest_of(&read_zip(&td));
        let dirs = m.get("directories").unwrap().as_array().unwrap();
        assert_eq!(dirs[0].get("count").unwrap().as_i64(), Some(2));
        assert_eq!(dirs[0].get("truncated").unwrap().as_bool(), Some(true));
    }

    #[test]
    fn collect_rejects_wrong_shapes() {
        let td = TestDir::new("shapes");
        // A directory passed as a collected file.
        let spec = td.spec_json(&format!(
            "\"files\":[\"{}\"]",
            json_escape(&td.path().to_string_lossy())
        ));
        assert_eq!(collect(&spec).unwrap_err().0, ERR_INVALID_ARG);
        // Output into a directory that does not exist.
        let out = td.path().join("ghost/bundle.zip");
        let spec = format!(
            "{{\"output_zip\":\"{}\"}}",
            json_escape(&out.to_string_lossy())
        );
        assert_eq!(collect(&spec).unwrap_err().0, ERR_NOT_FOUND);
        // The output may not also be an input.
        let f = td.write("self.bin", b"x");
        let out = td.path().join("self.bin");
        let spec = format!(
            "{{\"output_zip\":\"{}\",\"files\":[\"{}\"]}}",
            json_escape(&out.to_string_lossy()),
            json_escape(&f.to_string_lossy())
        );
        assert_eq!(collect(&spec).unwrap_err().0, ERR_INVALID_ARG);
    }
}
