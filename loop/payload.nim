## Plaintext content: the payload modes, the seeded per-worker
## generator, and the buffer fill from the operating-system CSPRNG.

import ./state

proc getrandom(buf: pointer, buflen: csize_t, flags: cuint): int
  {.importc: "getrandom", header: "<sys/random.h>", discardable.}
  ## Nim-specific. The standard library's random-source module reaches
  ## the kernel through a raw syscall on Linux; the C entry is declared
  ## here instead so the fill goes through the same libc wrapper every
  ## other implementation calls.

const payloadNames = [
  "fixed", "rotating", "pattern-zero", "pattern-ff", "pattern-ascii",
]
  ## Payload mode selector values for the --payload-mode flag.
  ##
  ##   - fixed: one CSPRNG-generated buffer per worker, held unchanged
  ##     for the whole run (the default).
  ##   - rotating: the buffer is regenerated before every iteration, so
  ##     no two encrypt calls see the same plaintext.
  ##   - pattern-zero / pattern-ff: degenerate constant fills (all 0x00
  ##     / all 0xFF) probing minimum-entropy plaintext handling.
  ##   - pattern-ascii: a repeating 'A'..'Z' ramp probing low-entropy
  ##     structured text.

proc payloadModeName*(mode: PayloadMode): string =
  payloadNames[ord(mode)]

proc parsePayloadMode*(s: string, outMode: var PayloadMode): bool =
  for i, name in payloadNames:
    if s == name:
      outMode = PayloadMode(i)
      return true
  false

proc seedWorker*(seed: uint64, workerId: int): uint64 =
  ## Seeded plaintext. The seed makes plaintext content reproducible so
  ## a failing iteration can be replayed with the same bytes; it
  ## governs nothing else — pipeline keys, nonces and masters stay
  ## CSPRNG-drawn, so a seeded run is a reproduction aid and never a
  ## security test. Each worker's stream is domain-separated by its id
  ## so seeded workers still hold pairwise-distinct buffers under the
  ## fixed and rotating modes. The generator is splitmix64: a few lines
  ## in any language, which is why it is the one every binding uses.
  seed + uint64(workerId) + 1'u64

proc splitmix64(state: var uint64): uint64 =
  state = state + 0x9E3779B97F4A7C15'u64
  var z = state
  z = (z xor (z shr 30)) * 0xBF58476D1CE4E5B9'u64
  z = (z xor (z shr 27)) * 0x94D049BB133111EB'u64
  z xor (z shr 31)

proc fillRandom*(buf: var openArray[byte]): bool =
  ## Fills `buf` from the operating-system CSPRNG. The syscall returns
  ## at most ~33 MiB per call and may return short on a signal, so the
  ## fill loops until every byte is in place.
  var off = 0
  while off < buf.len:
    let r = getrandom(addr buf[off], csize_t(buf.len - off), 0)
    if r <= 0:
      return false
    off += r
  true

proc fillPayload*(mode: PayloadMode, seeded: bool, rng: var uint64,
                  buf: var openArray[byte]): bool =
  ## Writes one plaintext buffer according to the payload mode. The
  ## fixed and rotating modes draw from the seeded generator when the
  ## run is seeded and from the OS CSPRNG otherwise; the pattern modes
  ## are deterministic regardless of the seed. Returns false when the
  ## CSPRNG fails.
  case mode
  of pmFixed, pmRotating:
    if not seeded:
      return fillRandom(buf)
    var i = 0
    while i < buf.len:
      let v = splitmix64(rng)
      let take = min(buf.len - i, 8)
      copyMem(addr buf[i], unsafeAddr v, take)
      i += 8
    true
  of pmPatternZero:
    if buf.len > 0:
      zeroMem(addr buf[0], buf.len)
    true
  of pmPatternFF:
    for i in 0 ..< buf.len:
      buf[i] = 0xFF'u8
    true
  of pmPatternAscii:
    for i in 0 ..< buf.len:
      buf[i] = byte(ord('A') + (i mod 26))
    true
