// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::fmem::extent::AddressExtent;

#[test]
fn validates_half_open_ranges() {
    let extent = AddressExtent {
        start: 0x1000,
        end: 0x1100,
        index: 0x1080,
    };

    assert!(extent.is_well_formed());
    assert!(extent.contains_range(0x80));
    assert!(!extent.contains_range(0x81));
}

#[test]
fn accepts_only_zero_length_at_end() {
    let extent = AddressExtent {
        start: 4,
        end: 8,
        index: 8,
    };

    assert!(extent.contains_range(0));
    assert!(!extent.contains_range(1));
}

#[test]
fn rejects_indices_outside_extent() {
    assert!(
        !AddressExtent {
            start: 4,
            end: 8,
            index: 3
        }
        .contains_range(0)
    );
    assert!(
        !AddressExtent {
            start: 4,
            end: 8,
            index: 9
        }
        .contains_range(0)
    );
}

#[test]
fn rejects_malformed_extent_without_subtraction_overflow() {
    let extent = AddressExtent {
        start: 8,
        end: 4,
        index: 6,
    };

    assert!(!extent.is_well_formed());
    assert!(!extent.contains_range(0));
}
