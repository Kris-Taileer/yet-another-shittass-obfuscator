
CC      ?= cc
OBJCOPY ?= objcopy

CFLAGS_HOST = -O2 -Wall
CFLAGS_STUB = -nostdlib -ffreestanding -static -no-pie -fno-pic \
              -fno-stack-protector -fcf-protection=none \
              -fno-asynchronous-unwind-tables -Os -T stub.ld
CFLAGS_TGT  = -nostdlib -ffreestanding -static -no-pie -fno-pic \
              -fno-stack-protector -fcf-protection=none \
              -fno-asynchronous-unwind-tables -O2 -Wl,-e,_start

.PHONY: all run clean

all: protected

packer: packer.c
	$(CC) $(CFLAGS_HOST) -o $@ $<

stub.elf: stub.c obf.S
	$(CC) $(CFLAGS_STUB) -o $@ $^

stub.bin: stub.elf
	$(OBJCOPY) -O binary $< $@

target: target_hello.c
	$(CC) $(CFLAGS_TGT) -o $@ $<
	strip --strip-all $@

protected: packer stub.bin target
	./packer target $@

run: protected
	./protected

clean:
	rm -f packer stub.elf stub.bin target protected
