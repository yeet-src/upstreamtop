.PHONY: all clean

ARCH    ?= $(shell uname -m | sed 's/x86_64/x86/; s/aarch64/arm64/')
CLANG   ?= clang

# Prefer the bpf headers that ship with libbpf-sys (so this builds without
# system libbpf-dev). Fall back to /usr/include if the libbpf-sys build
# artifact isn't around.
LIBBPF_INCLUDE := $(firstword $(wildcard \
    ../../crates/target/release/build/libbpf-sys-*/out/include) \
    /usr/include)

CFLAGS = -O2 -g -Wall -target bpf \
         -D__TARGET_ARCH_$(ARCH) \
         -I. -I$(LIBBPF_INCLUDE)

all: upstreamtop.bpf.o

upstreamtop.bpf.o: upstreamtop.bpf.c
	$(CLANG) $(CFLAGS) -c $< -o $@

clean:
	rm -f upstreamtop.bpf.o
