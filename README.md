# DiagKit

## TL;DR

One call that gathers a diagnostics bundle for any Windows app: point it at the logs, dumps and configs you want, and it writes a single ZIP plus a `manifest.json` that says exactly what's inside — every entry's size and SHA-256, version-resource details for the binaries you ask about, listings of the folders you name, and a small environment block. No more "send me the log… now hash the exe… now which build is that DLL" scavenger hunts: the bundle answers all of it at once, and its caps and name rules mean a bundle can never silently swallow the wrong file or grow without bound.

```c
#include "diagkit.h"

int main(void) {
    char *r = di_collect(
        "{\"output_zip\":\"C:/diag/bundle.zip\","
         "\"app_name\":\"MyApp\","
         "\"files\":[\"C:/logs/app.log\",\"C:/data/crash.dmp\"],"
         "\"directories\":[{\"path\":\"C:/data\"}],"
         "\"file_info\":[\"C:/app/MyApp.exe\"],"
         "\"env\":true,"
         "\"extra_text\":{\"notes.txt\":\"crashed on save\"}}");
    if (!r) { printf("failed: %s\n", di_last_error()); return 1; }
    printf("%s\n", r);   /* {"zip":"C:/diag/bundle.zip","entries":4,"bytes":...} */
    di_free_string(r);
}
```

## Why this exists

When a field test fails, the evidence is never in one place: there's the app log, maybe a crash dump, the settings file, and the open question of whether the DLL on that machine is even the build everyone thinks it is. Each answer takes a round trip, and each answer changes the next question. DiagKit collapses that into one call the app makes when something goes wrong (or a support flow asks the user to make):

- **Collect** the files that matter into one ordinary ZIP (STORED entries, readable by any unzip tool).
- **Describe** the binaries that matter — size, SHA-256, and on Windows the strings from the file's version resource — without storing them, in the manifest's `file_info`.
- **List** the folders that matter — recursive names + sizes, never contents — so "was the file even there?" is answerable from the manifest alone.
- **Record** the environment basics (OS, architecture, computer name) when asked, and nothing else about the machine.
- **Prove the bundle's own integrity**: every stored entry is in the manifest with its SHA-256, so whoever receives the bundle can verify nothing was swapped or truncated in transit.

## The manifest

Every bundle carries `manifest.json` at its root, written last (it cannot list itself):

```json
{"kit":"DiagKit","kit_version":"0.1.0","created_utc":"2026-10-28T18:39:59Z",
 "app_name":"MyApp",
 "entries":[{"name":"logs/app.log","size":12044,"sha256":"…"}],
 "file_info":[{"path":"C:/app/MyApp.exe","size":…,"sha256":"…",
               "version":{"FileVersion":"1.9.0","ProductName":"MyApp"}}],
 "directories":[{"path":"C:/data","count":2,"truncated":false,
                 "entries":[{"path":"a.txt","size":10}]}],
 "env":{"os":"windows","arch":"x86_64","computer_name":"DESKTOP-1"}}
```

`version` is `null` when the file has no version resource — and always `null` off Windows, where size + SHA-256 are what you get. `env` is `null` unless the spec asked for it.

## Names and caps — the safety contract

Entry names are derived from each file's canonical path (components joined with `/`, root and drive dropped), so they can never contain `..` or point outside the bundle. Two files deriving the same name are disambiguated with ` (2)`, ` (3)`, … — never overwritten, never dropped. Caller-chosen `extra_text` names are validated against the same rules and rejected when they break them, and `manifest.json` is reserved.

Caps are errors, never truncations, and they name the file that broke them: one stored entry at most **64 MiB**, the whole bundle at most **256 MiB** of stored content. They're enforced twice — from file sizes before anything is read, and again on the running totals while streaming, so a log file growing mid-collection still can't slip past. A directory listing holds at most **5000** entries (a per-directory `max_files` may ask for fewer) and says `"truncated": true` when the cap cut it.

A missing input is a clean error (`DI_ERR_NOT_FOUND`) naming the path — a bundle silently missing its main log is worse than no bundle. The bundle is written to a temporary sibling and renamed into place, so a failed collection never leaves a partial zip behind.

## The API in one screen

| Area | Calls |
|---|---|
| Collect | `di_collect` (spec JSON → result JSON `{"zip","entries","bytes"}`, or NULL + last-error) |
| Errors | Integer `DI_*` codes + thread-local `di_last_error()` / `di_last_error_code()` |
| Strings | Results are caller-owned; free with `di_free_string` |

Spec keys: `output_zip` (required, absolute; parent must exist), `app_name`, `files`, `directories` (`{path, max_files?}`), `file_info`, `env`, `extra_text`. Unknown and duplicate keys are parse errors, never ignored. The header documents every rule in full.

## Honest caveats

- **STORED means stored.** v0.1 writes entries uncompressed — bundles of text logs will be larger than a compressed archive would be. DEFLATE is the v0.2 headline (see ROADMAP); v0.1 chose a writer small enough to audit end to end.
- **Version strings are Windows-only, and their runtime is Unverified.** The version-resource path compiles and checks clean for `x86_64-pc-windows-msvc`, but no Windows machine has run it yet — an on-machine field pass is the remaining proof. Off Windows, `version` is simply `null`.
- **A directory listing can skip what it cannot read.** Unreadable *sub*directories are skipped (a locked subfolder shouldn't sink the whole bundle); an unreadable or missing root is an error. Listings never read file contents, and symlinks are listed but never followed.
- **Files are read as they are.** If a file changes while being collected, the bundle holds the bytes as read and the manifest hashes match the bytes in the bundle (hashes are computed during the write) — but a file's manifest size may differ from a size you stat afterwards.
- **Nothing leaves the machine.** DiagKit has no network code and no upload path; the bundle goes exactly where `output_zip` says.

## Verification status

27 tests: SHA-256 against the published FIPS vectors (including the million-`a` case) in one-shot and awkward-chunk streaming forms; CRC-32 against the standard check values; the ZIP writer read back by walking the central directory, extracting via local headers and verifying CRCs — plus, during development, a real bundle verified externally by `unzip -t` and Python's `zipfile` (both clean); spec parsing (unknown/duplicate keys, wrong types, missing and relative `output_zip`); entry-name validation (traversal, absolute, drive, backslash, reserved manifest name) and the collision-suffix rule; and full collections against real temp files — manifest contents matching the collected bytes, missing inputs as clean `DI_ERR_NOT_FOUND` errors, both size caps enforced from sparse files, directory-listing caps with the truncated flag, and the output-may-not-be-an-input guard. The full WinDevKit gate (fmt, clippy on host and `x86_64-pc-windows-msvc`, check on the Windows target, whole suite) is green locally. **The Windows version-resource runtime is Unverified** until a field pass runs it on a real machine; Windows CI's real MSVC build remains the link gate.

Building: `cargo build --release` → `diagkit.dll` / `libdiagkit.so`; `cargo test --locked`.

License: MIT. Part of the WinDevKit family — see `AGENTS.md` for build discipline and `ROADMAP.md` for what's next.
