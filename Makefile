.PHONY: all clean

# A failed/interrupted bpftool dump must not leave a partial vmlinux.h
# behind — make would treat the half-written file as up to date and the
# build would fail confusingly downstream. Delete targets on recipe error.
.DELETE_ON_ERROR:

ARCH    ?= $(shell uname -m | sed 's/x86_64/x86/; s/aarch64/arm64/')
CLANG   ?= clang
BPFTOOL ?= sudo bpftool
STRIP   ?= strip

# Prefer the bpf headers that ship with libbpf-sys (so this builds without
# system libbpf-dev). Fall back to /usr/include if the libbpf-sys build
# artifact isn't around.
LIBBPF_INCLUDE := $(firstword $(wildcard \
    ../../crates/target/release/build/libbpf-sys-*/out/include) \
    /usr/include)

CFLAGS = -O2 -g -Wall -target bpf \
         -D__TARGET_ARCH_$(ARCH) \
         -I. -Iinclude -I$(LIBBPF_INCLUDE)

all: upstreamtop.bpf.o

# The packet-header structs (ethhdr, iphdr, tcphdr), struct __sk_buff, and
# the IPPROTO_* enum come from the running kernel's BTF — CO-RE, no
# system linux/*.h headers needed.
include/vmlinux.h:
	@mkdir -p include
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

upstreamtop.bpf.o: upstreamtop.bpf.c include/vmlinux.h
	$(CLANG) $(CFLAGS) -c $< -o $@
	# Drop DWARF but keep .BTF, which yeet needs to load the program.
	$(STRIP) --strip-debug $@

clean:
	rm -f upstreamtop.bpf.o include/vmlinux.h
