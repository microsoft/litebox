// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Occupy the canonical serialized near page with a guest file mapping.
// AOT installation must relocate its prebuilt pair to fresh VA.
#define ISLAND_MAPPING_PAGES 4
#include "island_retirement.c"
