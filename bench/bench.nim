## Micro-benchmarks for the Nim binding: encryptMessage (Single
## Message profile) and stream-session encrypt (Streaming Non-AEAD
## profile) throughput at 1 MiB / 16 MiB / 64 MiB. Wall-clock via
## std/monotimes; output is a fixed-width table:
##
##   bench             size     mb_per_sec
##   message           1 MiB    <n>
##   ...
##
## Configuration is driven by environment variables so a side-by-side
## comparison with the root Go bench harness is straightforward:
##
##   ITB_NONCE_BITS      512         shipped secure default
##   ITB_KEY_BITS        1024        matches root Go BENCH3.md table
##   ITB_WITH_PARALLAX   false       root Go bench runs without parallax
##   ITB_WITH_WRAPPER    false       root Go bench runs without the wrapper
##   ITB_INNER_HASH      (profile)   opaque hash name
##   ITB_MSG_PROFILE     (fallback ITB_PROFILE, then singlemsg-triple-nomac-v1)
##   ITB_STREAM_PROFILE  (fallback ITB_PROFILE, then streaming-noaead-triple-v1)
##   ITB_BENCH_MIN_SEC   5           per-case wall-clock budget (seconds)

import std/[monotimes, os, strformat, strutils, sysrand, times]
import ../src/itb

## Per-case iteration floor alongside the wall-clock budget.
const BenchMinIters = 3
const Sizes = [1 shl 20, 16 shl 20, 64 shl 20]

proc benchMinSeconds(): float =
  let v = try: parseFloat(getEnv("ITB_BENCH_MIN_SEC", "5"))
          except ValueError: 5.0
  if v > 0: v else: 5.0

proc envIsTrue(name: string): bool =
  getEnv(name) in ["true", "1"]

proc buildOpts(): Opts =
  ## Reads the bench-shape env vars and builds the opts. Defaults
  ## match root Go BENCH3.md so numbers are directly comparable.
  result = Opts()
    .withRaw("nonceBits", getEnv("ITB_NONCE_BITS", "512"))
    .withRaw("keyBits", getEnv("ITB_KEY_BITS", "1024"))
    .withParallax(envIsTrue("ITB_WITH_PARALLAX"))
    .withWrapper(envIsTrue("ITB_WITH_WRAPPER"))
  let inner = getEnv("ITB_INNER_HASH")
  if inner.len > 0:
    result = result.withInnerHash(inner)
  let macName = getEnv("ITB_MAC_NAME")
  if macName.len > 0:
    result = result.withMacName(macName)

proc profileName(shapeEnv, fallback: string): string =
  let s = getEnv(shapeEnv)
  if s.len > 0: return s
  let p = getEnv("ITB_PROFILE")
  if p.len > 0: p else: fallback

proc sizeLabel(size: int): string =
  if size >= (1 shl 20): $(size shr 20) & " MiB"
  else: $(size shr 10) & " KiB"

proc randomPayload(n: int): seq[byte] =
  ## CSPRNG-fill so plaintext content matches the root Go bench
  ## (crypto/rand). Chunked to stay within per-call getrandom limits.
  result = newSeq[byte](n)
  var off = 0
  while off < n:
    let want = min(1 shl 20, n - off)
    let piece = urandom(want)
    copyMem(addr result[off], unsafeAddr piece[0], want)
    off += want

proc benchCase(name: string, size: int, body: proc ()) =
  ## Runs the body until the wall-clock budget is spent (with an
  ## iteration floor + one untimed warm-up), then prints one table
  ## row.
  body() # warm-up
  let budget = benchMinSeconds()
  let start = getMonoTime()
  var elapsed = 0.0
  var iters = 0
  while elapsed < budget or iters < BenchMinIters:
    body()
    inc iters
    elapsed = (getMonoTime() - start).inNanoseconds.float / 1e9
  let mb = size.float * iters.float / (1024.0 * 1024.0)
  echo &"{name:<17} {sizeLabel(size):<8} {mb / elapsed:.1f}"

proc benchMessage() =
  let pipe = initPipeline(profileName("ITB_MSG_PROFILE",
                                      "singlemsg-triple-nomac-v1"),
                          buildOpts())
  for size in Sizes:
    let plain = randomPayload(size) # not in the timing loop
    # Pooled output buffer: encryptMessageInto grows it once during
    # warm-up, then every timed iteration reuses it allocation-free.
    var wire: seq[byte]
    benchCase("message", size, proc () =
      discard pipe.encryptMessageInto(plain, wire))
    # Pre-encrypt one wire outside the decrypt timing loop.
    let decWire = pipe.encryptMessage(plain)
    var decOut: seq[byte]
    benchCase("message-dec", size, proc () =
      discard pipe.decryptMessageInto(decWire, decOut))
  pipe.free()

proc benchStreamOneShot() =
  ## Whole-buffer stream: one FFI round trip through
  ## encryptStreamOneShot / decryptStreamOneShot per iteration.
  let pipe = initPipeline(profileName("ITB_STREAM_PROFILE",
                                      "streaming-noaead-triple-v1"),
                          buildOpts())
  for size in Sizes:
    let plain = randomPayload(size)
    # Pooled output buffer: encryptStreamOneShotInto grows it once
    # during warm-up, then every timed iteration reuses it
    # allocation-free.
    var wire: seq[byte]
    benchCase("stream_one_shot", size, proc () =
      discard pipe.encryptStreamOneShotInto(plain, wire))
    # Pre-encrypt one wire outside the decrypt timing loop.
    let decWire = pipe.encryptStreamOneShot(plain)
    var decOut: seq[byte]
    benchCase("stream_one_shot-dec", size, proc () =
      discard pipe.decryptStreamOneShotInto(decWire, decOut))
  pipe.free()

proc benchStream() =
  let pipe = initPipeline(profileName("ITB_STREAM_PROFILE",
                                      "streaming-noaead-triple-v1"),
                          buildOpts())
  for size in Sizes:
    let plain = randomPayload(size)
    # Pooled drain buffer, reused across every readInto call of every
    # timed iteration.
    var chunk = newSeq[byte](PumpBuf)
    benchCase("stream", size, proc () =
      let enc = pipe.encryptStream()
      var off = 0
      while off < plain.len:
        let upto = min(off + PumpBuf, plain.len)
        enc.write(plain.toOpenArray(off, upto - 1))
        off = upto
        # Drain available output so the spool stays bounded.
        while true:
          let (n, _) = enc.readInto(chunk)
          if n == 0:
            break
      enc.endStream()
      while true:
        let (_, finished) = enc.readInto(chunk)
        if finished:
          break
      enc.free())
    # Pre-encrypt one wire outside the decrypt timing loop.
    var wireParts: seq[byte]
    block:
      let enc = pipe.encryptStream()
      var off = 0
      while off < plain.len:
        let upto = min(off + PumpBuf, plain.len)
        enc.write(plain.toOpenArray(off, upto - 1))
        off = upto
        while true:
          let (n, _) = enc.readInto(chunk)
          if n == 0: break
          wireParts.add(chunk[0 ..< n])
      enc.endStream()
      while true:
        let (n, finished) = enc.readInto(chunk)
        if n > 0: wireParts.add(chunk[0 ..< n])
        if finished: break
      enc.free()
    let decWire = wireParts
    benchCase("stream-dec", size, proc () =
      let dec = pipe.decryptStream()
      var off = 0
      while off < decWire.len:
        let upto = min(off + PumpBuf, decWire.len)
        dec.write(decWire.toOpenArray(off, upto - 1))
        off = upto
        while true:
          let (n, _) = dec.readInto(chunk)
          if n == 0: break
      dec.endStream()
      while true:
        let (_, finished) = dec.readInto(chunk)
        if finished: break
      dec.free())
  pipe.free()

when isMainModule:
  # Bench-scale allocation churn leaks Go scratch heap unboundedly
  # without a soft memory cap + aggressive GC; the return values
  # report the previous settings, not an error.
  discard setMemoryLimit(512 * 1024 * 1024)
  discard setGcPercent(20)

  echo &"""{"bench":<17} {"size":<8} mb_per_sec"""
  benchMessage()
  benchStream()
  benchStreamOneShot()
