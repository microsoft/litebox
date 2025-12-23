# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

SRC = rtld_audit.c
OUT_DIR ?= .
OUTPUT = $(OUT_DIR)/litebox_rtld_audit.so
CC ?= cc
CFLAGS ?= -Wall -Werror -fPIC -shared -nostdlib
ARCH ?= $(shell uname -m)
ifeq ($(ARCH),x86_64)
    CFLAGS += -m64
else
    $(error Unsupported target architecture: $(ARCH))
endif
ifdef DEBUG
    CFLAGS += -DDEBUG
endif
all: $(OUTPUT)

$(OUTPUT): $(SRC)
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(OUTPUT)

.PHONY: all clean
