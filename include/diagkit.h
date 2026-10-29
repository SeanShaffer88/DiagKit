/* DiagKit.dll — one-call diagnostics bundles: collect an
 * app's logs, dumps and configs into a single ZIP with a
 * JSON manifest that says exactly what is inside, what the
 * interesting files hash to, and (on Windows) what their
 * version resources claim.
 *
 * The problem this solves: when a field test fails, the
 * evidence hunt is a scavenger run — "send me the log",
 * "which build is the DLL, exactly", "hash the exe" — one
 * question per round trip. DiagKit is the one call that
 * answers all of it at once:
 *
 *   char *r = di_collect(
 *       "{\"output_zip\":\"C:/diag/bundle.zip\","
 *        "\"app_name\":\"MyApp\","
 *        "\"files\":[\"C:/logs/app.log\",\"C:/data/crash.dmp\"],"
 *        "\"file_info\":[\"C:/app/MyApp.exe\"],"
 *        "\"env\":true}");
 *   if (!r) printf("failed: %s\n", di_last_error());
 *   else { printf("%s\n", r); di_free_string(r); }
 *   // r == {"zip":"C:/diag/bundle.zip","entries":3,"bytes":...}
 *
 * THE SPEC (one JSON object; unknown keys are an error —
 * DI_ERR_PARSE — never ignored, and duplicate keys in one
 * object are a parse error too):
 *
 *   output_zip  (string, REQUIRED) absolute path of the
 *               ZIP to write. The parent directory must
 *               already exist. The bundle is written to a
 *               temporary sibling and renamed into place,
 *               so a failed collection never leaves a
 *               partial zip at this path.
 *   app_name    (string, optional) recorded in the
 *               manifest verbatim.
 *   files       (array of strings, optional) absolute
 *               paths of files to STORE in the bundle.
 *               A missing file is an error
 *               (DI_ERR_NOT_FOUND) that names it — a
 *               bundle silently missing its main log is
 *               worse than no bundle. A directory here is
 *               DI_ERR_INVALID_ARG (use "directories").
 *   directories (array of objects, optional) folders to
 *               LIST, not store: {"path": <absolute path>,
 *               "max_files": <uint, optional>}. The
 *               manifest gains a recursive listing of file
 *               names + sizes (never contents), sorted,
 *               capped at 5000 entries per directory (or
 *               max_files when smaller), with a
 *               "truncated" flag when the cap cut it.
 *               Symlinks are listed, never followed.
 *               Unreadable SUBdirectories are skipped;
 *               an unreadable or missing root is an error.
 *   file_info   (array of strings, optional) absolute
 *               paths to DESCRIBE in the manifest without
 *               storing: {path, size, sha256, version}.
 *               "version" is an object of the strings from
 *               the file's Windows version resource
 *               (CompanyName, FileDescription, FileVersion,
 *               ProductName, ProductVersion,
 *               LegalCopyright, OriginalFilename — those
 *               present), or null when the file has no
 *               version resource, and always null off
 *               Windows. A missing path is
 *               DI_ERR_NOT_FOUND.
 *   env         (bool, optional, default false) when
 *               true, the manifest gains
 *               {"os":…, "arch":…, "computer_name":…} —
 *               the COMPUTERNAME environment variable when
 *               present, else null. Nothing else about the
 *               machine is collected.
 *   extra_text  (object of string→string, optional) extra
 *               entries stored verbatim under caller-chosen
 *               names, e.g. {"notes.txt": "what happened",
 *               "state/settings.json": "{...}"}. Names are
 *               validated (see ENTRY NAMES below) and a
 *               name already used by another entry is an
 *               error, never a silent rename.
 *
 * ENTRY NAMES. A stored file lands under a name derived
 * from its canonical path: normal components joined with
 * '/', root and drive dropped — C:\Users\x\app.log becomes
 * "Users/x/app.log", /var/log/app.log becomes
 * "var/log/app.log". Canonical paths contain no ".." or
 * ".", so derived names are traversal-safe by
 * construction. When two files derive the same name (the
 * same file listed twice, say), later ones are suffixed
 * " (2)", " (3)", … before the extension — a file is
 * never lost to a collision and entries never share a
 * name. Caller-chosen extra_text names must be relative,
 * '/'-separated, with no "..", "." or empty components,
 * no '\', no drive prefix and no control characters;
 * violations are DI_ERR_INVALID_ARG naming the entry.
 * "manifest.json" is reserved for the manifest itself:
 * an extra_text entry may not use it (error), and a
 * collected file that derives it is renamed by the
 * collision rule.
 *
 * CAPS (enforced twice — from file sizes before anything
 * is read, and again on the running totals while
 * streaming, so a file that grows mid-collection still
 * cannot slip past):
 *
 *   one stored entry   at most 64 MiB  (64 * 1024 * 1024)
 *   whole bundle       at most 256 MiB (256 * 1024 * 1024)
 *                      of stored content
 *
 * Breaking either is DI_ERR_TOO_LARGE and the message
 * names the file — caps are errors, never truncations.
 *
 * THE BUNDLE. An ordinary ZIP archive, entries STORED
 * (no compression in v0.1), readable by any unzip tool.
 * Layout: the collected files (spec order), then the
 * extra_text entries (spec order), then "manifest.json"
 * at the root:
 *
 *   {"kit":"DiagKit","kit_version":"0.1.0",
 *    "created_utc":"2026-10-28T18:39:59Z",
 *    "app_name":"MyApp" | null,
 *    "entries":[{"name":…,"size":…,"sha256":…}, …],
 *    "file_info":[{"path":…,"size":…,"sha256":…,
 *                   "version":{…} | null}, …],
 *    "directories":[{"path":…,"count":…,"truncated":…,
 *                     "entries":[{"path":…,"size":…}, …]}, …],
 *    "env":{"os":…,"arch":…,"computer_name":…} | null}
 *
 * "entries" in the manifest lists every stored content
 * entry (files + extra_text) with the SHA-256 of its
 * bytes; the manifest cannot list itself. SHA-256 and
 * CRC-32 are computed by the library (zero dependencies).
 *
 * RESULT. di_collect returns a caller-owned JSON string:
 *
 *   {"zip": <output_zip as given>, "entries": <count>,
 *    "bytes": <size of the written zip file>}
 *
 * "entries" counts every entry in the archive, including
 * manifest.json. On failure di_collect returns NULL and
 * sets the thread-local last error; no partial bundle is
 * left at output_zip.
 *
 * All strings are UTF-8, NUL-terminated. char* results
 * are caller-owned: free with di_free_string(). Errors
 * set a thread-local di_last_error() (message + code).
 */
#ifndef DIAGKIT_H
#define DIAGKIT_H

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32) && defined(DI_BUILD)
#define DI_API __declspec(dllexport)
#elif defined(_WIN32)
#define DI_API __declspec(dllimport)
#else
#define DI_API
#endif

enum {
    DI_OK = 0,
    DI_ERR_INVALID_ARG = 1,   /* missing/empty/wrong-typed values, bad entry names, relative output_zip */
    DI_ERR_NOT_SUPPORTED = 2,
    DI_ERR_NOT_FOUND = 3,     /* a named input file/directory, or the output directory, does not exist */
    DI_ERR_ACCESS_DENIED = 4,
    DI_ERR_PLATFORM = 5,      /* an OS call failed; see di_last_error() */
    DI_ERR_INTERNAL = 6,
    DI_ERR_PARSE = 7,         /* spec is not valid JSON, or has an unknown or duplicate key */
    DI_ERR_TOO_LARGE = 8      /* a size cap was exceeded; the message names the file */
};

DI_API const char *di_version(void);
DI_API const char *di_last_error(void);
DI_API int di_last_error_code(void);
DI_API void di_free_string(char *p);

/* Collect a diagnostics bundle from a spec JSON object
 * (see above). Returns a caller-owned result JSON string,
 * or NULL on failure with the last-error set. */
DI_API char *di_collect(const char *spec_json);

#ifdef __cplusplus
}
#endif
#endif /* DIAGKIT_H */
