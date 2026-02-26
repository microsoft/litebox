CLANG ?= clang
TARGET ?= x86_64-apple-macos10.15
ZIG ?= zig
ZIG_TARGET ?= x86_64-macos
MACOS_RUNTIME_DIR ?= litebox_runner_macos_on_linux_userland/test_binaries/.macos_runtime
MACOS_RUNTIME_DYLD ?= $(MACOS_RUNTIME_DIR)/usr/lib/dyld
MACOS_RUNTIME_LIBSYSTEM ?= $(MACOS_RUNTIME_DIR)/usr/lib/libSystem.B.dylib
RUNTIME_FILE_ARGS := --runtime-file /usr/lib/dyld=$(MACOS_RUNTIME_DYLD) --runtime-file /usr/lib/libSystem.B.dylib=$(MACOS_RUNTIME_LIBSYSTEM)
LOCAL_MACOS_RUNTIME_DYLD := ../../$(MACOS_RUNTIME_DYLD)
LOCAL_MACOS_RUNTIME_LIBSYSTEM := ../../$(MACOS_RUNTIME_LIBSYSTEM)

DOCKER_OSX_IMAGE ?= sickcodes/docker-osx:latest
DOCKER_OSX_CONTAINER ?= litebox-docker-osx
DOCKER_OSX_SSH_PORT ?= 50922
DOCKER_OSX_USER ?= user
DOCKER_OSX_PASS ?= alpine
DOCKER_OSX_START_TIMEOUT ?= 1800
DOCKER_OSX_KEEP_RUNNING ?= 0

SAMPLE_SRC := hello_puts_semantic_macos.s
SAMPLE_BIN := hello_puts_semantic_macos
DYNAMIC_SRC := hello_dynamic_macos.s
DYNAMIC_BIN := hello_dynamic_macos
DYLD_STUB_SRC := dyld_stub_macos.s
DYLD_STUB_BIN := dyld_stub_macos
ZIG_BASIC_SRC := zig_basic.c
ZIG_BASIC_BIN := zig_basic_macos
ZIG_IO_SRC := zig_io_mm.c
ZIG_IO_BIN := zig_io_mm_macos

.PHONY: all sample dynamic check-zig check-runtime-bundle populate-macos-runtime build-zig-samples zig-basic zig-io test test-static test-dynamic test-zig-basic test-zig-io test-zig-basic-runtime test-zig-io-runtime test-zig-runtime clean

all: sample dynamic build-zig-samples

sample: $(SAMPLE_BIN)

dynamic: $(DYNAMIC_BIN) $(DYLD_STUB_BIN)

check-zig:
	@command -v $(ZIG) >/dev/null || { echo "zig toolchain not found; install zig and retry (e.g. ZIG=/path/to/zig make build-zig-samples)"; exit 1; }

check-runtime-bundle:
	@test -f "$(LOCAL_MACOS_RUNTIME_DYLD)" || { echo "Missing $(MACOS_RUNTIME_DYLD). Run 'make populate-macos-runtime' first."; exit 1; }
	@test -f "$(LOCAL_MACOS_RUNTIME_LIBSYSTEM)" || { echo "Missing $(MACOS_RUNTIME_LIBSYSTEM). Run 'make populate-macos-runtime' first."; exit 1; }

populate-macos-runtime:
	./populate_macos_runtime.sh \
		"$(MACOS_RUNTIME_DIR)" \
		"$(DOCKER_OSX_IMAGE)" \
		"$(DOCKER_OSX_CONTAINER)" \
		"$(DOCKER_OSX_SSH_PORT)" \
		"$(DOCKER_OSX_USER)" \
		"$(DOCKER_OSX_PASS)" \
		"$(DOCKER_OSX_START_TIMEOUT)" \
		"$(DOCKER_OSX_KEEP_RUNNING)"

build-zig-samples: check-zig zig-basic zig-io

zig-basic: $(ZIG_BASIC_BIN)

zig-io: $(ZIG_IO_BIN)

test: test-static test-dynamic

test-zig-basic: check-zig zig-basic
	cd ../.. && cargo run --bin litebox_runner_macos_on_linux_userland -- \
		litebox_runner_macos_on_linux_userland/test_binaries/$(ZIG_BASIC_BIN)

test-zig-io: check-zig zig-io
	cd ../.. && cargo run --bin litebox_runner_macos_on_linux_userland -- \
		litebox_runner_macos_on_linux_userland/test_binaries/$(ZIG_IO_BIN)

test-zig-basic-runtime: check-runtime-bundle check-zig zig-basic
	cd ../.. && cargo run --bin litebox_runner_macos_on_linux_userland -- \
		$(RUNTIME_FILE_ARGS) \
		litebox_runner_macos_on_linux_userland/test_binaries/$(ZIG_BASIC_BIN)

test-zig-io-runtime: check-runtime-bundle check-zig zig-io
	cd ../.. && cargo run --bin litebox_runner_macos_on_linux_userland -- \
		$(RUNTIME_FILE_ARGS) \
		litebox_runner_macos_on_linux_userland/test_binaries/$(ZIG_IO_BIN)

test-zig-runtime: test-zig-basic-runtime test-zig-io-runtime

test-static: sample
	cd ../.. && cargo run --bin litebox_runner_macos_on_linux_userland -- \
		litebox_runner_macos_on_linux_userland/test_binaries/$(SAMPLE_BIN)

test-dynamic: dynamic
	cd ../.. && cargo run --bin litebox_runner_macos_on_linux_userland -- \
		--runtime-file /usr/lib/dyld=litebox_runner_macos_on_linux_userland/test_binaries/$(DYLD_STUB_BIN) \
		litebox_runner_macos_on_linux_userland/test_binaries/$(DYNAMIC_BIN)

$(SAMPLE_BIN): $(SAMPLE_SRC)
	$(CLANG) --target=$(TARGET) -fuse-ld=lld -nostdlib -Wl,-no_pie -Wl,-e,_start -o $@ $<

$(DYNAMIC_BIN): $(DYNAMIC_SRC)
	$(CLANG) --target=$(TARGET) -fuse-ld=lld -nostdlib -Wl,-no_pie -Wl,-e,_main -o $@ $<

$(DYLD_STUB_BIN): $(DYLD_STUB_SRC)
	$(CLANG) --target=$(TARGET) -fuse-ld=lld -nostdlib -Wl,-no_pie -Wl,-e,_start -o $@ $<

$(ZIG_BASIC_BIN): $(ZIG_BASIC_SRC)
	$(ZIG) cc -target $(ZIG_TARGET) -nostdlib -fno-stack-protector -fno-pie -Wl,-e,_main -o $@ $<

$(ZIG_IO_BIN): $(ZIG_IO_SRC)
	$(ZIG) cc -target $(ZIG_TARGET) -nostdlib -fno-stack-protector -fno-pie -Wl,-e,_main -o $@ $<

clean:
	rm -f $(SAMPLE_BIN) $(DYNAMIC_BIN) $(DYLD_STUB_BIN) $(ZIG_BASIC_BIN) $(ZIG_IO_BIN)
