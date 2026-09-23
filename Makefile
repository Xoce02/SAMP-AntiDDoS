PORT ?= 7777
CLANG ?= clang
ARCH_INC ?= /usr/include/$(shell uname -m)-linux-gnu
TARGET_ARCH ?= x86

all: build/xdp_samp.o

build/xdp_samp.o: xdp_samp.c
	@mkdir -p build
	$(CLANG) -O2 -g -target bpf \
		-D__TARGET_ARCH_$(TARGET_ARCH) \
		-Dgameport=$(PORT) \
		-I$(ARCH_INC) \
		-c $< -o $@

clean:
	rm -rf build
