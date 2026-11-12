# yet-another-shittass-obfuscator
anti smt solver, anti debug, anti read and anti decompile obfuscator

A minimal ELF packer and obfuscator for Linux x86-64, written in C. It wraps a
program into a single self-contained binary that decompresses itself at runtime,
resists debugging, and obstructs decompilation. Each defense is implemented as a
separate, readable layer, and the layers are aimed specifically at corrupting
what a disassembler or decompiler reports -- not just making the right answer
slower to compute, but making the tool's own output wrong, which is exactly
the failure mode that turns automated and LLM-assisted analysis into
hallucination instead of a correct result.

This is an educational project. It is intended for studying software-protection
internals and should only be used on binaries you own. It does not make code
impossible to analyze; the goal is to raise the cost of analysis.

## Features

- LZSS compression and XOR encryption of all loadable segments, under a fresh
  random key generated per build (from `/dev/urandom`) and patched directly
  into the embedded stub. No two packed binaries share a key, so cracking one
  sample doesn't crack the rest.
- The container metadata -- original entry point, segment table, offsets --
  is encrypted with the same per-build key, not just the segment bytes.
  Nothing about the wrapped binary's layout is visible in the output file at
  rest; it only exists once the stub derives the correct key at runtime.
- Full symbol and section stripping (the output is a single anonymous segment).
- Anti-debugging folded into the decryption key rather than a branch, so it
  cannot be bypassed by patching a single conditional jump. The `ptrace`
  self-check runs inside a throwaway forked child that reports its verdict via
  exit code, so a real tracer is still detected but the process itself never
  becomes a tracee of its own launching shell.
- Lazy per-segment decompression via a SIGSEGV handler: a segment is decrypted
  only when first accessed, so untouched code never appears in memory in cleartext.
- Decrypted segments decay: a periodic timer physically wipes and
  re-`PROT_NONE`s any segment that isn't the one currently faulting, then lets
  the normal lazy-unpack path re-decrypt it on next touch. A memory snapshot
  (core dump, `/proc/pid/mem`) taken at an arbitrary moment only ever catches
  whatever's live right then, never the whole unpacked image at once --
  page-protection bits alone don't stop that kind of read, so the data itself
  has to go.
- Two composite guard functions (`obf_guard`, `obf_guard2`) that combine
  stack-pointer desync, opaque predicates, a junk opcode byte, and an
  indirect jump to break decompiler preconditions. Each guard's dead branch
  decodes under linear disassembly as a plausible but entirely fictitious
  instruction sequence (a bogus multi-byte `call`/`cmov` that eats the real
  code following it) -- the obfuscation isn't that the logic is hard to
  follow, it's that the disassembly itself is lying.

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
derived key is wrong, the container and payload decrypt to garbage, and the
process exits on its own.

Note for testing under `strace`/`gdb`: any attached tracer trips the anti-debug
check by design, so those tools can only ever observe the intentionally-broken
path, never the real one.

## How it works

```
Build:  input -> packer -> [compress+encrypt blob, encrypt container,
                             patch per-build key into stub] -> output
Run:    kernel -> stub -> anti-debug (forked ptrace probe, /proc status, rdtsc)
                       -> key -> decrypt container -> reserve memory (no access)
                       -> jump to original entry -> page fault
                       -> handler decrypts and unpacks that one segment
                       -> instruction retried -> program runs
                       -> timer tick -> decay: wipe + reset dormant segments
```

## Layout

```
packer.c      host tool: parse ELF, compress+encrypt blob and container,
              generate and patch the per-build key, embed the stub
stub.c        freestanding unpacker: anti-debug, container decrypt, lazy
              unpack, segment decay, jump to entry
obf.S         obf_guard / obf_guard2: identity at runtime, decompiler traps
              in static analysis
container.h   on-disk format shared by packer and stub
ks.h          keystream used for encryption, shared by packer and stub
```

## Limitations

Supports non-PIE, statically linked, x86-64 targets only. The output uses an
RWX segment, which may be rejected by kernels that enforce strict W^X. Every
layer is defeatable: anti-debugging can be bypassed under an emulator, the
decompiler traps can be removed manually, dynamic analysis follows the single
real execution path, and decay only raises the cost of a memory-dump attack --
a patient attacker can still snapshot across enough ticks to reassemble the
full image. The decay timer also adds runtime overhead and periodically
interrupts the protected program's own blocking syscalls (mitigated with
`SA_RESTART`, but not guaranteed for every syscall on every kernel).

## License

MIT
