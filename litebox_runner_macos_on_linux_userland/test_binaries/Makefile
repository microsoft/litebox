CLANG ?= clang
TARGET ?= x86_64-apple-macos10.15

SAMPLE_SRC := hello_puts_semantic_macos.s
SAMPLE_BIN := hello_puts_semantic_macos

.PHONY: all sample test clean

all: sample

sample: $(SAMPLE_BIN)

test: sample
	cd ../.. && cargo run --bin litebox_runner_macos_on_linux_userland -- litebox_runner_macos_on_linux_userland/test_binaries/$(SAMPLE_BIN)

$(SAMPLE_BIN): $(SAMPLE_SRC)
	$(CLANG) --target=$(TARGET) -fuse-ld=lld -nostdlib -Wl,-no_pie -Wl,-e,_start -o $@ $<

clean:
	rm -f $(SAMPLE_BIN)
