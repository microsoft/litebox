CLANG ?= clang
TARGET ?= x86_64-apple-macos10.15

SAMPLE_SRC := hello_puts_semantic_macos.s
SAMPLE_BIN := hello_puts_semantic_macos
DYNAMIC_SRC := hello_dynamic_macos.s
DYNAMIC_BIN := hello_dynamic_macos
DYLD_STUB_SRC := dyld_stub_macos.s
DYLD_STUB_BIN := dyld_stub_macos

.PHONY: all sample dynamic test test-static test-dynamic clean

all: sample dynamic

sample: $(SAMPLE_BIN)

dynamic: $(DYNAMIC_BIN) $(DYLD_STUB_BIN)

test: test-static test-dynamic

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

clean:
	rm -f $(SAMPLE_BIN) $(DYNAMIC_BIN) $(DYLD_STUB_BIN)
