// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// This file mapping explicitly owns the external serialized island page. The
// runtime fixture's 3-page mapping instead lets the allocator choose free VA.
#define ISLAND_MAPPING_PAGES 4
#include "island_retirement.c"
