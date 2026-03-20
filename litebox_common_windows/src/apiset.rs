// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! API-set remapping table.
//!
//! Modern Windows PE binaries import from "API-set" contract names like
//! `api-ms-win-crt-runtime-l1-1-0.dll` rather than physical DLL names.
//! This module maps those contract names to the physical DLLs that our
//! stub loader provides.

/// A mapping from an API-set contract prefix to a target DLL name.
struct ApiSetEntry {
    /// The prefix to match (lowercased, without `.dll` suffix).
    /// For example: `api-ms-win-crt-runtime-l1-1`
    prefix: &'static str,
    /// The DLL this maps to. For example: `ucrtbase.dll`
    target: &'static str,
}

/// Well-known API-set mappings needed for Node.js / UCRT / vcruntime.
///
/// These are a subset of the full Windows API-set schema. We only include
/// mappings for DLLs we actually provide stubs for (or bundle).
static API_SET_MAP: &[ApiSetEntry] = &[
    // CRT
    ApiSetEntry {
        prefix: "api-ms-win-crt-conio-l1-1",
        target: "ucrtbase.dll",
    },
    ApiSetEntry {
        prefix: "api-ms-win-crt-convert-l1-1",
        target: "ucrtbase.dll",
    },
    ApiSetEntry {
        prefix: "api-ms-win-crt-environment-l1-1",
        target: "ucrtbase.dll",
    },
    ApiSetEntry {
        prefix: "api-ms-win-crt-filesystem-l1-1",
        target: "ucrtbase.dll",
    },
    ApiSetEntry {
        prefix: "api-ms-win-crt-heap-l1-1",
        target: "ucrtbase.dll",
    },
    ApiSetEntry {
        prefix: "api-ms-win-crt-locale-l1-1",
        target: "ucrtbase.dll",
    },
    ApiSetEntry {
        prefix: "api-ms-win-crt-math-l1-1",
        target: "ucrtbase.dll",
    },
    ApiSetEntry {
        prefix: "api-ms-win-crt-multibyte-l1-1",
        target: "ucrtbase.dll",
    },
    ApiSetEntry {
        prefix: "api-ms-win-crt-private-l1-1",
        target: "ucrtbase.dll",
    },
    ApiSetEntry {
        prefix: "api-ms-win-crt-process-l1-1",
        target: "ucrtbase.dll",
    },
    ApiSetEntry {
        prefix: "api-ms-win-crt-runtime-l1-1",
        target: "ucrtbase.dll",
    },
    ApiSetEntry {
        prefix: "api-ms-win-crt-stdio-l1-1",
        target: "ucrtbase.dll",
    },
    ApiSetEntry {
        prefix: "api-ms-win-crt-string-l1-1",
        target: "ucrtbase.dll",
    },
    ApiSetEntry {
        prefix: "api-ms-win-crt-time-l1-1",
        target: "ucrtbase.dll",
    },
    ApiSetEntry {
        prefix: "api-ms-win-crt-utility-l1-1",
        target: "ucrtbase.dll",
    },
    // Core — On modern Windows (10+), most api-ms-win-core-* API sets
    // resolve to kernelbase.dll, which contains the real implementations.
    // kernel32.dll is a thin re-export wrapper that imports FROM these
    // same api-sets, so mapping them back to kernel32.dll creates
    // circular import thunks.
    ApiSetEntry {
        prefix: "api-ms-win-core-console-l1-1",
        target: "kernelbase.dll",
    },
    ApiSetEntry {
        prefix: "api-ms-win-core-console-l1-2",
        target: "kernelbase.dll",
    },
    ApiSetEntry {
        prefix: "api-ms-win-core-datetime-l1-1",
        target: "kernelbase.dll",
    },
    ApiSetEntry {
        prefix: "api-ms-win-core-debug-l1-1",
        target: "kernelbase.dll",
    },
    ApiSetEntry {
        prefix: "api-ms-win-core-errorhandling-l1-1",
        target: "kernelbase.dll",
    },
    ApiSetEntry {
        prefix: "api-ms-win-core-file-l1-1",
        target: "kernelbase.dll",
    },
    ApiSetEntry {
        prefix: "api-ms-win-core-file-l1-2",
        target: "kernelbase.dll",
    },
    ApiSetEntry {
        prefix: "api-ms-win-core-file-l2-1",
        target: "kernelbase.dll",
    },
    ApiSetEntry {
        prefix: "api-ms-win-core-handle-l1-1",
        target: "kernelbase.dll",
    },
    ApiSetEntry {
        prefix: "api-ms-win-core-heap-l1-1",
        target: "kernelbase.dll",
    },
    ApiSetEntry {
        prefix: "api-ms-win-core-heap-l2-1",
        target: "kernelbase.dll",
    },
    ApiSetEntry {
        prefix: "api-ms-win-core-interlocked-l1-1",
        target: "kernelbase.dll",
    },
    ApiSetEntry {
        prefix: "api-ms-win-core-io-l1-1",
        target: "kernelbase.dll",
    },
    ApiSetEntry {
        prefix: "api-ms-win-core-libraryloader-l1-2",
        target: "kernelbase.dll",
    },
    ApiSetEntry {
        prefix: "api-ms-win-core-localization-l1-2",
        target: "kernelbase.dll",
    },
    ApiSetEntry {
        prefix: "api-ms-win-core-memory-l1-1",
        target: "kernelbase.dll",
    },
    ApiSetEntry {
        prefix: "api-ms-win-core-namedpipe-l1-1",
        target: "kernelbase.dll",
    },
    ApiSetEntry {
        prefix: "api-ms-win-core-processenvironment-l1-1",
        target: "kernelbase.dll",
    },
    ApiSetEntry {
        prefix: "api-ms-win-core-processenvironment-l1-2",
        target: "kernelbase.dll",
    },
    ApiSetEntry {
        prefix: "api-ms-win-core-processthreads-l1-1",
        target: "kernelbase.dll",
    },
    ApiSetEntry {
        prefix: "api-ms-win-core-profile-l1-1",
        target: "kernelbase.dll",
    },
    ApiSetEntry {
        prefix: "api-ms-win-core-realtime-l1-1",
        target: "kernelbase.dll",
    },
    ApiSetEntry {
        prefix: "api-ms-win-core-registry-l1-1",
        target: "kernelbase.dll",
    },
    ApiSetEntry {
        prefix: "api-ms-win-core-apiquery-l1-1",
        target: "ntdll.dll",
    },
    ApiSetEntry {
        prefix: "api-ms-win-core-delayload-l1-1",
        target: "kernelbase.dll",
    },
    ApiSetEntry {
        prefix: "api-ms-win-core-job-l1-1",
        target: "kernelbase.dll",
    },
    ApiSetEntry {
        prefix: "api-ms-win-core-largeinteger-l1-1",
        target: "kernelbase.dll",
    },
    ApiSetEntry {
        prefix: "api-ms-win-core-libraryloader-l2-1",
        target: "kernelbase.dll",
    },
    ApiSetEntry {
        prefix: "api-ms-win-core-namedpipe-l1-2",
        target: "kernelbase.dll",
    },
    ApiSetEntry {
        prefix: "api-ms-win-core-rtlsupport-l1-1",
        target: "ntdll.dll",
    },
    ApiSetEntry {
        prefix: "api-ms-win-core-rtlsupport-l1-2",
        target: "ntdll.dll",
    },
    ApiSetEntry {
        prefix: "api-ms-win-core-string-l1-1",
        target: "kernelbase.dll",
    },
    ApiSetEntry {
        prefix: "api-ms-win-core-synch-l1-1",
        target: "kernelbase.dll",
    },
    ApiSetEntry {
        prefix: "api-ms-win-core-synch-l1-2",
        target: "kernelbase.dll",
    },
    ApiSetEntry {
        prefix: "api-ms-win-core-sysinfo-l1-1",
        target: "kernelbase.dll",
    },
    ApiSetEntry {
        prefix: "api-ms-win-core-sysinfo-l1-2",
        target: "kernelbase.dll",
    },
    ApiSetEntry {
        prefix: "api-ms-win-core-threadpool-l1-1",
        target: "kernelbase.dll",
    },
    ApiSetEntry {
        prefix: "api-ms-win-core-threadpool-legacy-l1-1",
        target: "kernelbase.dll",
    },
    ApiSetEntry {
        prefix: "api-ms-win-core-threadpool-private-l1-1",
        target: "kernelbase.dll",
    },
    ApiSetEntry {
        prefix: "api-ms-win-core-timezone-l1-1",
        target: "kernelbase.dll",
    },
    ApiSetEntry {
        prefix: "api-ms-win-core-util-l1-1",
        target: "kernelbase.dll",
    },
    // Security
    ApiSetEntry {
        prefix: "api-ms-win-security-base-l1-1",
        target: "advapi32.dll",
    },
    ApiSetEntry {
        prefix: "api-ms-win-security-base-l1-2",
        target: "advapi32.dll",
    },
    // Eventing
    ApiSetEntry {
        prefix: "api-ms-win-eventing-provider-l1-1",
        target: "kernelbase.dll",
    },
    // Fibers
    ApiSetEntry {
        prefix: "api-ms-win-core-fibers-l1-1",
        target: "kernelbase.dll",
    },
    // Process snapshot
    ApiSetEntry {
        prefix: "api-ms-win-core-processsnapshot-l1-1",
        target: "kernelbase.dll",
    },
    // Sockets
    ApiSetEntry {
        prefix: "api-ms-win-core-comm-l1-1",
        target: "kernelbase.dll",
    },
];

/// Resolve an API-set contract name to a physical DLL name.
///
/// The input `dll_name` should be the full import name (e.g.,
/// `api-ms-win-crt-runtime-l1-1-0.dll`). The matching is case-insensitive
/// and matches on prefix up through the major version. Only the trailing
/// patch version (a `-` followed by digits) is ignored; arbitrary suffixes
/// like `api-ms-win-core-file-l1-1foo.dll` will **not** match.
///
/// Returns the target DLL name if a match is found, or `None` if the name
/// is not an API-set contract.
pub fn resolve_apiset(dll_name: &str) -> Option<&'static str> {
    // API-set names always start with "api-" or "ext-"
    let lower = dll_name_to_lower(dll_name);
    let lower = lower.trim_end_matches(".dll");

    if !lower.starts_with("api-") && !lower.starts_with("ext-") {
        return None;
    }

    // Match against our table. The table entries store the contract name up
    // through major version (e.g., "api-ms-win-core-file-l1-1"). A valid
    // match has either nothing remaining, or a patch-version suffix of the
    // form "-<digits>".
    for entry in API_SET_MAP {
        if let Some(rest) = lower.strip_prefix(entry.prefix)
            && (rest.is_empty() || is_patch_version_suffix(rest))
        {
            return Some(entry.target);
        }
    }

    // Unknown API-set contract — return None so the caller can log a warning.
    None
}

/// Returns true if the given DLL name looks like an API-set contract.
pub fn is_apiset_name(dll_name: &str) -> bool {
    let lower = dll_name_to_lower(dll_name);
    lower.starts_with("api-") || lower.starts_with("ext-")
}

/// Lowercase a DLL name for matching.
fn dll_name_to_lower(s: &str) -> alloc::string::String {
    let mut out = alloc::string::String::with_capacity(s.len());
    for b in s.bytes() {
        out.push(b.to_ascii_lowercase() as char);
    }
    out
}

/// Returns true if `s` is a valid patch-version suffix: `-` followed by one
/// or more ASCII digits (e.g., `-0`, `-1`, `-42`).
fn is_patch_version_suffix(s: &str) -> bool {
    let rest = match s.strip_prefix('-') {
        Some(r) => r,
        None => return false,
    };
    !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_apiset_valid_names() {
        // Exact prefix (no patch version)
        assert_eq!(
            resolve_apiset("api-ms-win-crt-runtime-l1-1.dll"),
            Some("ucrtbase.dll")
        );
        // With patch version -0
        assert_eq!(
            resolve_apiset("api-ms-win-crt-runtime-l1-1-0.dll"),
            Some("ucrtbase.dll")
        );
        // With patch version -1
        assert_eq!(
            resolve_apiset("api-ms-win-core-file-l1-1-1.dll"),
            Some("kernelbase.dll")
        );
        // Case-insensitive
        assert_eq!(
            resolve_apiset("API-MS-WIN-CRT-RUNTIME-L1-1-0.DLL"),
            Some("ucrtbase.dll")
        );
    }

    #[test]
    fn resolve_apiset_rejects_malformed() {
        // Arbitrary suffix after prefix (not a patch version)
        assert_eq!(resolve_apiset("api-ms-win-core-file-l1-1foo.dll"), None);
        // Extra text after patch digit
        assert_eq!(resolve_apiset("api-ms-win-core-file-l1-1-0abc.dll"), None);
        // Not an api-set at all
        assert_eq!(resolve_apiset("kernel32.dll"), None);
    }
}
