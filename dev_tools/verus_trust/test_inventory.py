# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

import unittest

from inventory import layout_violations, scan_source, summarize


class InventoryTests(unittest.TestCase):
    def test_comments_literals_and_lifetimes(self):
        source = """
// assume(false);
/* #[verifier::external_body] /* admit(); */ */
const TEXT: &str = r###"assume_specification[f]();"###;
const OTHER: &str = "admit(); \\" quote";
const CHAR: char = '"';
fn checked<'a>(x: &'a str) {}
assume(false);
"""
        findings = scan_source(source, "fixture.rs")
        self.assertEqual([(f["category"], f["start_line"]) for f in findings],
                         [("assumed_fact", 8)])

    def test_full_multiline_contract_and_same_line_deduplication(self):
        source = """pub assume_specification<T>[take](x: &mut T) -> (r: T)
    ensures match Some(r) {
        Some(value) => value == *old(x),
        None => false,
    },
;
assume(true); assume(false);
"""
        findings = scan_source(source, "assumptions/mem.rs")
        contract = findings[0]
        self.assertEqual(contract["end_line"], 6)
        self.assertIn("None => false", contract["source"])
        summary = summarize(findings)
        self.assertEqual(summary["assumed_fact"], {"entries": 2, "source_lines": 1})
        self.assertEqual(summary["assumed_contract"]["source_lines"], 6)

    def test_attribute_groups_and_cfg_branches_are_not_coverage(self):
        source = """#[cfg(verus_keep_ghost)]
#[verifier::external_type_specification]
#[verifier::external_body]
pub struct Opaque(T);
#[cfg_attr(verus_keep_ghost, verifier::external_body)]
fn excluded() {}
#[verus_verify(external_derive)]
struct Checked(u32);
#[verifier::external_fn_specification]
fn binding() {}
"""
        findings = scan_source(source, "native.rs")
        self.assertEqual([f["category"] for f in findings], [
            "opaque_type_registration", "excluded_body", "excluded_derive",
            "external_function_binding",
        ])
        self.assertEqual(findings[0]["end_line"], 3)

    def test_new_assumption_in_property_source_rejected(self):
        findings = scan_source("assume(false);", "vlitebox/src/properties/example.rs")
        self.assertEqual(len(layout_violations(findings)), 1)
        findings = scan_source("pub assume_specification[f]() -> bool;",
                               "vlitebox-thirdparty/src/assumptions/example.rs")
        self.assertEqual(layout_violations(findings), [])

    def test_malformed_contract_is_not_silently_truncated(self):
        with self.assertRaises(ValueError):
            scan_source("pub assume_specification[f]() ensures true", "broken.rs")


if __name__ == "__main__":
    unittest.main()
