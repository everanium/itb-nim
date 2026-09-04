# ITB Nim Binding

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, OSCCA's SM-series in China, IC3S in India, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia, CRYPTREC in Japan, KCMVP in South Korea) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

Thin Nim proxy over the libitb shared library's `ITB_Triple_*`
surface (`cmd/cshared`). Runtime FFI via `{.importc, dynlib.}`
declarations — no compile-time link against libitb; the
`.so` / `.dylib` / `.dll` is resolved and loaded at program start.
Every hash-name / MAC-name / cipher-name / profile-name is an opaque
string passed through to Go for validation; the binding carries no
ITB construction logic. The public surface is the `itb` module
(`initPipeline` / `loadPipeline` / `loadPipelineF` / `version`, the
`Profile` record with `register` / `lookup` / `profiles` / `inspect`,
and the Go runtime knobs), the `Pipeline`
type (Single Message encrypt / decrypt, save / saveF, rekey,
maxWorkers, close, incremental stream sessions), the
`StreamEncryptor` / `StreamDecryptor` session types, an `Opts`
query-string builder for init overrides, and an `ItbError` exception
carrying the `Status` code plus the `ITB_LastError` diagnostic.

## Prerequisites (Arch Linux)

```bash
sudo pacman -S go nim
```

Generic Linux / macOS: a Go toolchain and Nim 1.6+ (developed and
tested against Nim 2.2). Windows: the same; libitb builds as
`libitb.dll`. No third-party Nim packages are required — the binding
uses only the standard library.

## Build

The convenience driver builds `libitb.so`, type-checks the Nim
sources, and compiles the eitb CLI in one step:

```bash
./bindings/nim/build.sh
```

Equivalent manual invocation:

```bash
go build -trimpath -buildmode=c-shared \
    -o dist/linux-amd64/libitb.so ./cmd/cshared
cd bindings/nim && nim check src/itb.nim
```

The library is importable directly from `bindings/nim/src` (add
`--path:bindings/nim/src` or a nimble `requires` on the local
package); `itb.nimble` declares the package for nimble-based
consumption.

## Library lookup order

1. `ITB_LIBITB_PATH` environment variable (path to the shared
   library file).
2. `<repo>/dist/<os>-<arch>/libitb.<ext>` resolved by walking up
   from the executable's directory (in-repo builds).
3. The OS default loader path (`LD_LIBRARY_PATH`, `ld.so.cache`,
   `DYLD_LIBRARY_PATH`, `PATH`).

## Usage example

```nim
import itb

let sender = initPipeline("singlemsg-triple-mac-v1")
let receiver = loadPipeline(sender.save)

let wire = sender.encryptMessage("any text or binary data")
let plain = receiver.decryptMessage(wire)

sender.free()
receiver.free()
```

`Opts` overrides the profile default at init (chunk size, outer
cipher, parallax on/off, wrapper on/off, MAC name, palette, worker
cap); every setter returns the updated builder for fluent chaining.
The resolved shape travels inside the blob, so the receiver needs no
options of its own:

```nim
let opts = Opts().withChunkSize(65536).withWrapper(false).withMaxWorkers(4)
let sender = initPipeline("singlemsg-triple-mac-v1", opts)
let receiver = loadPipeline(sender.save)
```

`rekey` rotates the parallax + wrapper masters mid-session (the
eight ITB seeds and MAC key are fixed for the session lifetime by
design) and returns the fresh blob; the receiver picks up the new
masters by loading it:

```nim
var perm: array[32, byte]; var wrap: array[32, byte]
for i in 0 ..< 32: perm[i] = 0x11'u8; wrap[i] = 0x22'u8
let rotated = sender.rekey(perm, wrap)
let receiver = loadPipeline(rotated)
```

The same rotation is available on the receiver side as a master
override pair on load: `loadPipeline(blob, perm, wrap)` reopens the
blob with fresh masters folded in.

## Persisting sessions

The blob returned by `save` is a self-describing session bundle: it
carries the resolved profile record, the inner key material, and the
parallax / wrapper masters. `loadPipeline` reconstructs a Pipeline
from it without naming a profile.

```nim
let blob = sender.save                          # current blob bytes
let receiver = loadPipeline(blob)               # reopen from bytes
sender.saveF("session.blob")                    # write to a file (mode 0600)
let receiver2 = loadPipelineF("session.blob")   # reopen from a file
let profile = inspect(blob)                     # metadata only, no Pipeline
assert profile.name == "singlemsg-triple-mac-v1"
```

`inspect` decodes the embedded `Profile` record without constructing
a Pipeline. `saveF` / `loadPipelineF` perform the file access inside
libitb.

Load works for blobs generated with shipped primitives (every entry in
the shipped catalogue). Blobs generated by Go programs that use
`hashes.Register` or `macs.Register` to install custom primitives
cannot be loaded through this binding — the receiver must use the Go
library directly and register the same custom primitive under the
same name before opening. Attempting to load such a blob through this
binding raises `ItbError` with `stRecipePrimitiveUnknown`.

**Runtime tuning.** The worker cap is per-machine and never travels
in the blob; the receiver may pick its own after load:

```nim
receiver.maxWorkers(4)   # clamped by libitb; <= 0 selects auto
```

## Profile registry

`register` installs a user-defined profile under a new name from a
`Profile` record; `lookup` reads a registered record back; `profiles`
lists every registered name. The record's field rules are enforced by
libitb.

```nim
var custom = lookup("singlemsg-triple-nomac-v1")
custom.name = ""                 # a non-empty name must equal the register argument
custom.wrapper = false
custom.outerCipher = ""
register("my-nomac-plain", custom)
assert "my-nomac-plain" in profiles()
```

`encryptMessageInto` / `decryptMessageInto` are the allocation-free
counterparts: they write into a caller-owned `var seq[byte]` (grown as
needed, never shrunk) and return the byte count, so one pooled buffer
serves every call in a hot loop.

`encryptStream` / `decryptStream` open incremental sessions exposing
`write` / `endStream` / `read` / `drainAll` for caller-driven loops —
`readInto(buf)` drains into a caller-owned reusable buffer instead of
allocating a fresh chunk per call — plus a `pump(source, sink)` helper
that moves one `File` into another with bounded memory:

```nim
let pipe = initPipeline("streaming-noaead-triple-v1")
let enc = pipe.encryptStream()
enc.write(chunkA)
enc.write(chunkB)
let wire = enc.drainAll()
enc.free()
```

`Pipeline` and the stream sessions carry ORC destructors, so
un-freed handles are reclaimed eventually; explicit `free` releases
the Go-side state deterministically. Stream sessions hold a
reference to their parent `Pipeline`, so the parent cannot be
collected while a session is live.

Profile names, opts keys, and every primitive name are validated by
the Go side; a rejected string raises `ItbError` carrying the status
code (`status` / `statusCode`, values in the `Status` enum) plus the
`ITB_LastError` diagnostic (`lastError`).

## Memory

Two process-wide knobs constrain Go runtime arena pacing, readable
at libitb load time via env vars (`ITB_GOMEMLIMIT`, `ITB_GOGC`) and
adjustable at any time programmatically. Pass `-1` to query without
changing:

```nim
discard setMemoryLimit(512 * 1024 * 1024)
discard setGcPercent(20)
```

## Testing

```bash
./bindings/nim/run_tests.sh
```

The harness builds `libitb.so`, exports `ITB_LIBITB_PATH`, and runs
the `unittest` suite. The suite covers the library version, the
shipped profile list, Single Message and stream round trips,
tampered-wire rejection, closed-handle mapping, large-payload buffer
sizing, rekey, profile registration, and error mapping — surface
parity checks; the deep suite lives in Go under the shipped tree.

## Benchmarking

```bash
./bindings/nim/run_bench.sh
```

Micro-benches: `encryptMessage` and stream-session encrypt
throughput at 1 MiB / 16 MiB / 64 MiB. Shape and budget are driven
by env vars (`ITB_PROFILE`, `ITB_INNER_HASH`, `ITB_KEY_BITS`,
`ITB_NONCE_BITS`, `ITB_WITH_PARALLAX`, `ITB_WITH_WRAPPER`,
`ITB_BENCH_MIN_SEC`); the script pins the same defaults as the root
Go BENCH3.md table.

## eitb utility

A small CLI under `bindings/nim/eitb/` mirrors the shipped Go
`tools/eitb` scope for shell smoke tests (the launcher compiles the
binary on first use):

```bash
./bindings/nim/eitb/eitb version
./bindings/nim/eitb/eitb profiles
./bindings/nim/eitb/eitb encrypt singlemsg-triple-mac-v1 in.bin out.bin  # blob hex on stderr
./bindings/nim/eitb/eitb decrypt singlemsg-triple-mac-v1 <blob-hex> out.bin back.bin
```

`decrypt` reopens the session with `loadPipeline` from the blob hex;
the profile argument only selects the Single Message or streaming
cipher pair.

## itb3 CLI

The shipped `itb3` binary under `cmd/itb3/` of the main repository
generates profile files (`.json` on disk) that this binding reopens
via `loadPipelineF`; the same utility also encrypts and decrypts
files directly. See `cmd/itb3/README.md` for full usage.

## Limitations

- The binding wraps the Triple Pipeline surface only. The Low-Level
  seed / MAC / blob / wrapper / parallax APIs are not exposed — use
  the shipped Go core for those.
- Streaming-decrypt caveat: chunked Streaming AEAD verifies per
  chunk, so plaintext of verified chunks is released before a later
  chunk can fail authentication.
- `ITB_LastError` is process-global last-write-wins; the textual
  diagnostic attached to an `ItbError` may belong to a different
  call under concurrent FFI use. The status code is always
  attributable.
- `rekey` must not run concurrently with cipher calls or open stream
  sessions on the same `Pipeline`.
- Input buffers are borrowed at the FFI boundary for the duration of
  the call; outputs are freshly-allocated `seq[byte]` values.
- Blocking FFI calls (`write` on a saturated session, `read` after
  `endStream`) block the calling thread while Go-side cipher work
  runs.
- libitb must be reachable at program start through the lookup order
  above; a resolve failure surfaces as the Nim runtime's
  `could not load: libitb.so` diagnostic and terminates the process.
