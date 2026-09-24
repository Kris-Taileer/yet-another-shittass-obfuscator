# yet-another-shittass-obfuscator
anti smt solver, anti debug, anti read and anti decompile obfuscator

A minimal ELF packer and obfuscator for Linux x86-64, written in C. It wraps a
program into a single self-contained binary that decompresses itself at runtime,
resists debugging, and obstructs decompilation. Each defense is implemented as a
separate, readable layer.

This is an educational project. It is intended for studying software-protection
internals and should only be used on binaries you own. It does not make code
impossible to analyze; the goal is to raise the cost of analysis.

## Features

- LZSS compression and XOR encryption of all loadable segments.
- Full symbol and section stripping (the output is a single anonymous segment).
- Anti-debugging folded into the decryption key rather than a branch, so it
  cannot be bypassed by patching a single conditional jump.
- Lazy per-segment decompression via a SIGSEGV handler: a segment is decrypted
  only when first accessed, so untouched code never appears in memory in cleartext.
- A composite guard function (`obf_guard`) that combines stack-pointer desync,
  a junk byte, and an indirect jump to break decompiler preconditions.

## Build

```
./build.sh
```

or, if the Makefile has intact tab indentation:

```
make
```

On NixOS:

```
nix-shell -p gcc binutils gnumake --run ./build.sh
```

## Usage

```
./packer <input> <output>
```

The input must be a non-PIE, statically linked, x86-64 ELF:

```
gcc -static -no-pie -o myprog myprog.c
strip --strip-all myprog
./packer myprog myprog_protected
./myprog_protected
```

The protected binary behaves identically to the original. Under a debugger the
derived key is wrong, the payload decrypts to garbage, and the process exits on
its own.

## How it works

```
Build:  input -> packer -> [compress -> encrypt -> embed stub] -> output
Run:    kernel -> stub -> anti-debug -> key -> reserve memory (no access)
                       -> jump to original entry -> page fault
                       -> handler decrypts and unpacks that one segment
                       -> instruction retried -> program runs
```

## Layout

```
packer.c      host tool: parse ELF, compress, encrypt, embed the stub
stub.c        freestanding unpacker: anti-debug, lazy unpack, jump to entry
obf.S         obf_guard: identity at runtime, decompiler trap in static analysis
container.h   on-disk format shared by packer and stub
ks.h          keystream used for encryption, shared by packer and stub
```

## Limitations

Supports non-PIE, statically linked, x86-64 targets only. The output uses an
RWX segment, which may be rejected by kernels that enforce strict W^X. Every
layer is defeatable: anti-debugging can be bypassed under an emulator, the
decompiler traps can be removed manually, and dynamic analysis follows the
single real execution path.

## License

MIT
