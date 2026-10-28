# DiagKit Roadmap

## v0.1.0 (current)
One-call diagnostics bundles behind a C ABI: collect files into a STORED-entry ZIP, describe files (size, SHA-256, Windows version-resource strings) without storing them, list directories (names + sizes, capped, with a truncated flag), an optional environment block, caller-supplied text entries under validated names, and a `manifest.json` recording all of it. Size caps (64 MiB per entry, 256 MiB per bundle) enforced from sizes before reading and again while streaming; traversal-safe entry names with collision suffixing; temp-file + rename so failures never leave a partial bundle. SHA-256 and CRC-32 implemented in-crate (zero dependencies), pinned by published vectors.

## Next, in order
1. **Compression**: optional DEFLATE for stored entries (a per-spec `"compress": true`, defaulting to today's STORED behaviour so existing consumers' bundles don't change shape silently). Text logs — the most common bundle content — shrink several-fold. Needs the family's own DEFLATE writer or a justified dependency decision, data-descriptor + central-directory tests extended to method 8, and a recorded size/speed benchmark before any claim is made about either.
2. **Redaction rules**: a per-spec `"redact"` block — path globs whose entries are listed but not stored, and text patterns (literal or simple glob, not regex) scrubbed from stored text entries and from `extra_text` before writing, with the manifest recording that redaction happened (rule count per entry, never the redacted content). A diagnostics bundle is exactly the file a user is asked to send a stranger; v0.1's answer is "the caller chooses the files", and that stops being good enough the first time a log contains a token. Redaction must fail closed: an entry that can't be scrubbed cleanly is listed-not-stored, never stored unscrubbed.
3. **File selection by pattern and recency**: `files` entries may name a glob plus `"newest": N`, so "the last three logs, whatever they're called" is one spec line instead of the app pre-walking its own log folder. Selection results (what matched, what was picked) go in the manifest beside the entries they produced.
4. **Bundle verification call**: `di_verify(zip)` that re-reads a bundle and checks every manifest hash against the stored bytes, returning a verdict JSON — the receiving end of the integrity story v0.1 only tells from the producing end. Pure reader work; the central-directory reader already exists in the test suite's shape.

## Explicitly not planned
- Uploading or sending bundles anywhere: no network code, ever. Where a bundle goes is the caller's business; a diagnostics library that phones home would defeat its own purpose.
- Collecting registry, process, or event-log state: different evidence, different kits. DiagKit bundles files and facts about files.
- Encryption of bundles: a real need in some support flows, but key management is an app decision; a half-specified in-kit version would be worse than none. (Redaction, item 2, is the in-scope half of that problem.)
- ZIP64: unnecessary while the bundle cap is 256 MiB; it arrives only if the cap ever rises, and before the cap moves, not after.
