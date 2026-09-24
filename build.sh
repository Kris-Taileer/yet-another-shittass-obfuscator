#!/usr/bin/env bash
#
set -e
CC="${CC:-cc}"
OBJCOPY="${OBJCOPY:-objcopy}"

STUB_FLAGS="-nostdlib -ffreestanding -fno-pic -no-pie -fno-stack-protector \
-fcf-protection=none -fno-asynchronous-unwind-tables -Os -T stub.ld"
TGT_FLAGS="-nostdlib -ffreestanding -static -no-pie -fno-pic -fno-stack-protector \
-fcf-protection=none -fno-asynchronous-unwind-tables -O2 -Wl,-e,_start"

echo "[1/5] packer";       $CC -O2 -Wall -o packer packer.c
echo "[2/5] stub.elf";     $CC $STUB_FLAGS -o stub.elf stub.c obf.S
echo "[3/5] stub.bin";     $OBJCOPY -O binary stub.elf stub.bin
echo "[4/5] target_hello"; $CC $TGT_FLAGS -o target_hello target_hello.c; strip --strip-all target_hello
echo "[5/5] pack";         ./packer target_hello protected
echo "OK -> ./protected"
