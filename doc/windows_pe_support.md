# Windows PE support

This document records guest-visible Windows shim behavior that is intentionally
less complete than Windows while LiteBox's VM and object-manager support are
still evolving.

## Section object mappings

LiteBox does not yet support true shared mappings for Windows section objects.
The current `PageManager` can create independent anonymous page mappings, but it
does not have first-class shared anonymous backing that can be mapped at
multiple virtual addresses and kept coherent by the memory manager.

For pagefile-backed sections, the Windows shim therefore allows only one active
view of a section object at a time. A second concurrent
`NtMapViewOfSection` for the same pagefile section is rejected with
`STATUS_NOT_SUPPORTED`, even though Windows permits it. This is an intentional
safety restriction: allowing two independent anonymous mappings would create
two incoherent aliases for one section object.

The workaround is to make "one concurrent view" behave like Windows for the
supported lifecycle:

1. The shared `SectionObject` owns a byte-vector backing store for pagefile
   section contents.
2. Mapping a pagefile section creates anonymous pages and seeds them from that
   backing store.
3. Before a mapped range becomes unreadable, and again when the view is
   unmapped, the shim flushes readable guest bytes back into the backing store.
4. Unmapping releases the section object's active-view slot, so the same live
   section handle can be mapped again later and observe the bytes written by the
   previous view.

This means LiteBox supports `map -> write -> unmap -> remap` persistence for a
single pagefile section view, but not simultaneous shared views. Real shared
pagefile mappings require PageManager support for shared anonymous backing.

Image sections have a related limitation: LiteBox maps them as read/execute
image views and rejects writable image view requests with
`STATUS_SECTION_PROTECTION`. Windows can service writable image views with
copy-on-write or shared image-page behavior; LiteBox will need that backing
model before writable image views can be enabled safely.
