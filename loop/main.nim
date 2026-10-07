## Long-run stress harness. The loop utility holds one Pipeline handle
## per exercised cipher surface for minutes, hammers it with concurrent
## encrypt → decrypt → compare round-trips from N worker threads,
## rotates the outer masters and reopens the handle from its session
## blob on a schedule, and reports whether the process survived with
## every byte intact. It is the Nim binding's counterpart of the Go
## harness under tools/loop: the same flags, the same round structure,
## the same summary in both renderings.
##
## The default shape is full production: the Streaming AEAD profile
## with parallax on, wrapper on, hmac-blake3 MAC, Areion-SoEM-512 inner
## hash, 1024-bit keys, and the compile-in 512-bit nonce width, driven
## through a stream session by three workers for five minutes on 16 MiB
## plaintexts. Every worker owns a distinct CSPRNG-generated plaintext
## held for the whole run, so any cross-call state leakage inside the
## Pipeline surfaces as a data mismatch between workers rather than
## cancelling out.
##
## A failure is one of two things. A cipher, rekey or load call that
## returns a non-OK status is a worker error: the run stops, the
## summary lists it, the verdict is FAIL and the exit code 1. A
## round-trip that returns without error but with different bytes is a
## data mismatch: the process terminates on the spot with exit code 3,
## printing the worker, the iteration and the first differing offset,
## and no summary — the state that produced the wrong bytes is the
## evidence. A crash inside the shared library or the host runtime has
## no exit code of its own here; surfacing it is what the utility is
## for.
##
## Usage:
##
##   ./loop --duration 5m --goroutines 3 --shape stream --hash areion512 \
##          --mac hmac-blake3 --payload-size 16MB --memlimit auto \
##          --parallax on --wrapper on
##
## Ctrl-C triggers a graceful shutdown: in-flight iterations complete,
## then the partial summary prints.

import std/[atomics, os, posix, strutils]

import ../src/itb3

import ./payload
import ./size
import ./state
import ./summary
import ./worker

const
  DefaultStreamProfile = "streaming-aead-triple-mac-v1"
    ## Profiles the shape-based pair is built against when --profile is
    ## empty.
  DefaultMessageProfile = "singlemsg-triple-mac-v1"

  KeystreamFillCipher = "aescmac"
    ## The primitive supplied for the parallax palette and the outer
    ## cipher when a profile leaves them unnamed. AES-CMAC is
    ## PRF-grade, so it is sound outside the Interlocked Barrier, and
    ## it is the closest relative of the AES-based inner primitive
    ## whose profiles need this fill.

# ─── Flags ─────────────────────────────────────────────────────────

type
  RawFlags = object
    ## The raw flag values before validation.
    barrierFill: int
    blobCycleEvery: int64
    blobMode: int
    chunkSize: string
    drbg: string
    duration: string
    gogc: int
    gomaxprocs: int
    goroutines: int
    hash: string
    iterations: int64
    jsonOutput: bool
    keyBits: int
    mac: string
    memlimit: string
    memprofile: string
    nonceBits: int
    parallax: string
    payloadMode: string
    payloadSize: string
    profile: string
    rekeyEvery: int64
    seed: uint64
    shape: string
    wrapper: string

  Flag = object
    ## One command-line flag: its name, the type label the usage
    ## prints, the help text, the rendered default suffix, and the
    ## assignment that lands the raw value in its slot. Values are
    ## validated after the whole line is parsed.
    name: string
    typeLabel: string
    help: string
    boolean: bool
    defaultSuffix: string
    assign: proc (v: string): bool

proc defaults(): RawFlags =
  RawFlags(
    barrierFill: 0, blobCycleEvery: 0, blobMode: 1, chunkSize: "0", drbg: "",
    duration: "5m",
    gogc: 0, gomaxprocs: 0, goroutines: 3, hash: "areion512", iterations: 0,
    jsonOutput: false, keyBits: 0, mac: "hmac-blake3", memlimit: "auto",
    memprofile: "", nonceBits: 0, parallax: "on", payloadMode: "fixed",
    payloadSize: "16MB", profile: "", rekeyEvery: 0, seed: 0,
    shape: "stream", wrapper: "on")

proc flagTable(f: ptr RawFlags): seq[Flag] =
  ## The flag table, in alphabetical order (the order the usage
  ## prints). The default suffix is rendered from the slot while it
  ## still holds its default, so the usage can never disagree with the
  ## value the parse starts from.
  var t: seq[Flag]

  proc addInt(t: var seq[Flag], name: string, slot: ptr int, help: string) =
    t.add(Flag(name: name, typeLabel: "int", help: help, boolean: false,
      defaultSuffix: (if slot[] != 0: " (default " & $slot[] & ")" else: ""),
      assign: proc (v: string): bool =
        try: slot[] = parseInt(v) except ValueError: return false
        true))

  proc addInt64(t: var seq[Flag], name: string, slot: ptr int64, help: string) =
    t.add(Flag(name: name, typeLabel: "int", help: help, boolean: false,
      defaultSuffix: "",
      assign: proc (v: string): bool =
        try: slot[] = parseBiggestInt(v) except ValueError: return false
        true))

  proc addUint64(t: var seq[Flag], name: string, slot: ptr uint64, help: string) =
    t.add(Flag(name: name, typeLabel: "uint", help: help, boolean: false,
      defaultSuffix: "",
      assign: proc (v: string): bool =
        if v.len == 0 or v[0] == '-': return false
        try: slot[] = parseBiggestUInt(v) except ValueError: return false
        true))

  proc addString(t: var seq[Flag], name, label: string, slot: ptr string,
                 help: string) =
    t.add(Flag(name: name, typeLabel: label, help: help, boolean: false,
      defaultSuffix: (if slot[].len > 0: " (default \"" & slot[] & "\")" else: ""),
      assign: proc (v: string): bool =
        slot[] = v
        true))

  proc addBool(t: var seq[Flag], name: string, slot: ptr bool, help: string) =
    t.add(Flag(name: name, typeLabel: "", help: help, boolean: true,
      defaultSuffix: "",
      assign: proc (v: string): bool =
        if v == "true": slot[] = true
        elif v == "false": slot[] = false
        else: return false
        true))

  t.addInt("barrier-fill", addr f.barrierFill,
    "DRBG barrier fill margin: 1 | 2 | 4 | 8 | 16 | 32; 0 = profile default (1)")
  t.addInt64("blob-cycle-every", addr f.blobCycleEvery,
    "reopen each pipeline from its session blob every N iterations per worker; 0 = never")
  t.addInt("blob-mode", addr f.blobMode,
    "container floor sizing mode: 1 (per-region, default) | 2 (per-container)")
  t.addString("chunk-size", "string", addr f.chunkSize,
    "streaming chunk-size budget (e.g. 4MB); 0 = profile default; inert for pure message shape")
  t.addString("drbg", "string", addr f.drbg,
    "DRBG fill primitive name (see itb3 drbgs); empty = profile default (auto tier)")
  t.addString("duration", "duration", addr f.duration,
    "run duration (Go format: 30s / 5m / 1h); ignored when --iterations > 0")
  t.addInt("gogc", addr f.gogc,
    "GC trigger percentage; 0 = leave the runtime default")
  t.addInt("gomaxprocs", addr f.gomaxprocs,
    "Go runtime GOMAXPROCS override; 0 = inherit from the environment")
  t.addInt("goroutines", addr f.goroutines,
    "concurrent workers (1..10); on runtimes without parallelism values above 1 are clamped to 1")
  t.addString("hash", "string", addr f.hash, "inner ITB hash primitive name")
  t.addInt64("iterations", addr f.iterations,
    "fixed per-worker iteration count; 0 = duration-based")
  t.addBool("json-output", addr f.jsonOutput,
    "print the final summary as one compact JSON object instead of log lines")
  t.addInt("key-bits", addr f.keyBits,
    "per-seed key width in bits: 512 | 1024 | 2048; 0 = profile default (1024)")
  t.addString("mac", "string", addr f.mac, "MAC primitive name")
  t.addString("memlimit", "string", addr f.memlimit,
    "Go heap soft limit: auto (1GiB when goroutines <= 3, else 256MiB, applied only when the runtime has no limit) or a size (e.g. 512MB)")
  t.addString("memprofile", "string", addr f.memprofile,
    "write a Go runtime heap profile (pprof) to this path at the end of the run; empty = none")
  t.addInt("nonce-bits", addr f.nonceBits,
    "on-wire nonce width in bits: 128 | 256 | 512; 0 = profile default (512)")
  t.addString("parallax", "string", addr f.parallax, "parallax layer: on | off")
  t.addString("payload-mode", "string", addr f.payloadMode,
    "plaintext content: fixed | rotating | pattern-zero | pattern-ff | pattern-ascii")
  t.addString("payload-size", "string", addr f.payloadSize,
    "per-iteration plaintext size (e.g. 1MB / 16MB / 64MB)")
  t.addString("profile", "string", addr f.profile,
    "exercise this single registered triple profile (overrides --shape with the profile's surface); empty = shape-based profile pair")
  t.addInt64("rekey-every", addr f.rekeyEvery,
    "rotate the parallax + wrapper masters via Rekey every N iterations per worker; 0 = never")
  t.addUint64("seed", addr f.seed,
    "deterministic plaintext RNG seed for bug reproduction, NOT for security testing (pipeline keys stay CSPRNG-drawn); 0 = crypto/rand plaintexts")
  t.addString("shape", "string", addr f.shape,
    "cipher surface to exercise: stream | message | stream_one_shot | both")
  t.addString("wrapper", "string", addr f.wrapper, "wrapper layer: on | off")
  t

proc usage(table: seq[Flag]) =
  var text = "Usage of loop:\n"
  for fl in table:
    text.add("  -" & fl.name & (if fl.typeLabel.len > 0: " " else: "") &
             fl.typeLabel & "\n")
    text.add("    \t" & fl.help & fl.defaultSuffix & "\n")
  errRaw(text)

proc parseArgv(argv: seq[string], table: seq[Flag]): int =
  ## Parses argv into the raw flag values. Accepts -name value,
  ## --name value, -name=value and --name=value; a boolean flag takes
  ## no value unless given as -name=true / -name=false. Returns 0, 1
  ## for -h / --help (usage printed), or -1 after printing the error.
  var i = 0
  while i < argv.len:
    let arg = argv[i]
    if arg.len < 2 or arg[0] != '-':
      errLine("unexpected positional arguments: [" & arg & "]")
      return -1
    var name = arg[(if arg[1] == '-': 2 else: 1) .. ^1]
    if name == "h" or name == "help":
      usage(table)
      return 1
    var value = ""
    var haveValue = false
    let eq = name.find('=')
    if eq >= 0:
      value = name[eq + 1 .. ^1]
      haveValue = true
      name = name[0 ..< eq]
    var at = -1
    for k, candidate in table:
      if name == candidate.name:
        at = k
        break
    if at < 0:
      errLine("flag provided but not defined: -" & name)
      usage(table)
      return -1
    let fl = table[at]
    if not haveValue:
      if fl.boolean:
        value = "true"
      elif i + 1 < argv.len:
        inc i
        value = argv[i]
      else:
        errLine("flag needs an argument: -" & fl.name)
        return -1
    if not fl.assign(value):
      errLine("invalid value \"" & value & "\" for flag -" & fl.name)
      return -1
    inc i
  0

proc parseOnOff(v: string, outValue: var bool): bool =
  ## Maps "on" / "off" to a bool; false otherwise.
  if v == "on":
    outValue = true
    return true
  if v == "off":
    outValue = false
    return true
  false

proc hashRegistered(name: string): bool =
  ## Whether `name` is in the shipped hash registry the binding
  ## enumerates. The registry is the authority the flag validation
  ## reads; reaching it any other way would reach past the binding.
  try:
    return name in hashNames()
  except ItbError:
    return false

proc fillKeystreamLayers(name: string, opts: var Opts,
                         wantParallax, wantWrapper: bool): int =
  ## Folds a keystream primitive into opts for any layer the named
  ## profile leaves unfilled but the operator asked for.
  ##
  ## A profile built around a primitive that is safe only inside the
  ## Interlocked Barrier ships with no parallax palette and no outer
  ## cipher: both layers run outside the barrier, where that primitive
  ## would stand bare, so the recipe leaves them unnamed rather than
  ## naming a primitive that must not key them. Engaging either layer
  ## therefore needs a keystream-capable primitive supplied from
  ## outside the recipe; without it construction fails on a palette
  ## below its minimum or an unnamed outer cipher, and the primitive
  ## that most deserves stressing becomes the one that cannot be
  ## stressed with those layers engaged.
  ##
  ## Overrides fold into the resolved record the blob carries, so the
  ## receiver rebuilds the same shape from the blob alone.
  ##
  ## Nim-specific. The binding decodes the record into a typed value,
  ## so the unfilled state is an empty palette / outer-cipher field
  ## rather than an absent JSON key.
  ##
  ## Returns 1 when a layer was filled, 0 when none needed it, -1 on a
  ## lookup failure (message already printed).
  var record: Profile
  try:
    record = lookup(name)
  except ItbError:
    errLine("--profile \"" & name & "\" is not a registered triple profile")
    return -1
  var filled = 0
  if wantParallax and record.parallaxPalette.len == 0:
    opts = opts.withParallaxPalette(
      [KeystreamFillCipher, KeystreamFillCipher, KeystreamFillCipher])
    if record.parallaxSegmentSize == 0:
      # A recipe that never carried a palette never carried a segment
      # size either, and the schedule rejects zero.
      opts = opts.withParallaxSegmentSize(4093)
    filled = 1
  if wantWrapper and record.outerCipher.len == 0:
    opts = opts.withOuterCipher(KeystreamFillCipher)
    filled = 1
  filled

proc profileSurface(name: string, surface: var Shape): bool =
  ## Resolves a registered profile to the shape family its record's
  ## mode exposes by reading the record through the binding's lookup: a
  ## mode beginning with "streaming" exposes the stream surfaces, one
  ## beginning with "singlemsg" the message surface, "blob-only" none.
  ## Prints the validation message and returns false on rejection.
  var record: Profile
  try:
    record = lookup(name)
  except ItbError:
    errLine("--profile \"" & name & "\" is not a registered triple profile")
    return false
  if record.mode.startsWith("streaming"):
    surface = shStream
    return true
  if record.mode.startsWith("singlemsg"):
    surface = shMessage
    return true
  errLine("--profile \"" & name & "\" carries no cipher surface (blob-only mode)")
  false

proc narrowShape(requested, surface: Shape): Shape =
  ## Applies a --profile's surface to the requested shape: a
  ## message-surface profile forces message; a stream-surface profile
  ## keeps stream or stream_one_shot as requested and turns message or
  ## both into stream.
  if surface == shMessage: shMessage
  elif requested == shStreamOneShot: shStreamOneShot
  else: shStream

proc parseFlags(argv: seq[string], cfg: var Config): int =
  ## Builds the resolved config from argv. Returns 0, 1 for help, or -1
  ## after printing "loop: <message>" for the first failing rule.
  var f = defaults()
  let table = flagTable(addr f)
  let rc = parseArgv(argv, table)
  if rc != 0:
    return rc

  if not parseDuration(f.duration, cfg.durationNs) or cfg.durationNs <= 0:
    errLine("--duration must be positive, got " & f.duration)
    return -1
  cfg.iterations = f.iterations
  if cfg.iterations < 0:
    errLine("--iterations must be >= 0, got " & $cfg.iterations)
    return -1
  if f.goroutines < 1 or f.goroutines > MaxWorkers:
    errLine("--goroutines must be in 1.." & $MaxWorkers & ", got " & $f.goroutines)
    return -1
  # Concurrency mode. This binding runs shared-handle: Nim threads call
  # into one Pipeline handle concurrently, which the shared library
  # permits after construction, so --goroutines is the thread count
  # verbatim, never clamped.
  cfg.workersRequested = f.goroutines
  cfg.workers = f.goroutines
  if not parseShape(f.shape, cfg.shape):
    errLine("--shape must be stream | message | stream_one_shot | both, got \"" &
            f.shape & "\"")
    return -1
  if not hashRegistered(f.hash):
    errLine("--hash \"" & f.hash & "\" is not a registered hash primitive")
    return -1
  cfg.hash = f.hash
  cfg.mac = f.mac # validated by Init: the C ABI enumerates no MAC names
  if not parseSize(f.payloadSize, cfg.payload):
    errLine("--payload-size: invalid size \"" & f.payloadSize & "\"")
    return -1
  if cfg.payload < 1:
    errLine("--payload-size must be at least 1 byte")
    return -1
  if f.memlimit == "auto":
    cfg.memlimitAuto = true
    cfg.memlimit = if cfg.workers <= 3: 1'i64 shl 30 else: 256'i64 shl 20
  elif not parseSize(f.memlimit, cfg.memlimit):
    errLine("--memlimit: invalid size \"" & f.memlimit & "\"")
    return -1
  cfg.gogc = f.gogc
  if cfg.gogc < 0:
    errLine("--gogc must be >= 0, got " & $cfg.gogc)
    return -1
  if not parseOnOff(f.parallax, cfg.parallax):
    errLine("--parallax must be on | off, got \"" & f.parallax & "\"")
    return -1
  if not parseOnOff(f.wrapper, cfg.wrapper):
    errLine("--wrapper must be on | off, got \"" & f.wrapper & "\"")
    return -1
  cfg.profile = f.profile
  if cfg.profile.len > 0:
    var surface: Shape
    if not profileSurface(cfg.profile, surface):
      return -1
    cfg.shape = narrowShape(cfg.shape, surface)
  cfg.keyBits = f.keyBits
  if cfg.keyBits notin [0, 512, 1024, 2048]:
    errLine("--key-bits must be 512 | 1024 | 2048 (or 0 = profile default), got " &
            $cfg.keyBits)
    return -1
  cfg.nonceBits = f.nonceBits
  if cfg.nonceBits notin [0, 128, 256, 512]:
    errLine("--nonce-bits must be 128 | 256 | 512 (or 0 = profile default), got " &
            $cfg.nonceBits)
    return -1
  cfg.blobMode = f.blobMode
  if cfg.blobMode notin [1, 2]:
    errLine("--blob-mode must be 1 (per-region) | 2 (per-container), got " &
            $cfg.blobMode)
    return -1
  cfg.barrierFill = f.barrierFill
  if cfg.barrierFill notin [0, 1, 2, 4, 8, 16, 32]:
    errLine("--barrier-fill must be 1 | 2 | 4 | 8 | 16 | 32 (or 0 = profile default), got " &
            $cfg.barrierFill)
    return -1
  cfg.drbg = f.drbg # validated by Init: the C ABI enumerates no DRBG names
  if not parseSize(f.chunkSize, cfg.chunkSize):
    errLine("--chunk-size: invalid size \"" & f.chunkSize & "\"")
    return -1
  cfg.gomaxprocs = f.gomaxprocs
  if cfg.gomaxprocs < 0:
    errLine("--gomaxprocs must be > 0 when specified, got " & $cfg.gomaxprocs)
    return -1
  cfg.rekeyEvery = f.rekeyEvery
  if cfg.rekeyEvery < 0:
    errLine("--rekey-every must be >= 0, got " & $cfg.rekeyEvery)
    return -1
  cfg.blobCycleEvery = f.blobCycleEvery
  if cfg.blobCycleEvery < 0:
    errLine("--blob-cycle-every must be >= 0, got " & $cfg.blobCycleEvery)
    return -1
  if not parsePayloadMode(f.payloadMode, cfg.payloadMode):
    errLine("--payload-mode must be fixed | rotating | pattern-zero | pattern-ff | pattern-ascii, got \"" &
            f.payloadMode & "\"")
    return -1
  cfg.seed = f.seed
  cfg.jsonOutput = f.jsonOutput
  cfg.memprofile = f.memprofile
  0

# ─── Signals ───────────────────────────────────────────────────────

var signalSeen: cint = 0

proc onSignal(sig: cint) {.noconv.} =
  signalSeen = 1

proc cSignal(sig: cint, handler: pointer): pointer
  {.importc: "signal", header: "<signal.h>", discardable.}
  ## Nim-specific. The runtime leaves SIGPIPE ignored, so a write to a
  ## closed stdout raises instead of ending the process. Restoring the
  ## signal's default disposition ends it on the spot, which is what
  ## every other implementation does and what a fleet driver expects.
  ## The restore is the first thing `run` does, ahead of the first
  ## line printed: a write that fails before it would end the run with
  ## a stack trace instead of the signal.

proc installSignals() =
  ## Graceful stop. SIGINT / SIGTERM set a flag the main thread polls
  ## while it waits for the workers; it turns the flag into the stop
  ## request every worker checks before starting an iteration, so a
  ## signal interrupts nothing mid-call — the in-flight encrypt /
  ## decrypt / compare completes, the worker returns, and the partial
  ## summary prints with the verdict the completed iterations earned.
  var sa: Sigaction
  sa.sa_handler = onSignal
  discard sigemptyset(sa.sa_mask)
  sa.sa_flags = 0
  discard sigaction(SIGINT, sa)
  discard sigaction(SIGTERM, sa)

# ─── Pipelines ─────────────────────────────────────────────────────

proc logPipelineInitialised(profileName: string, blob: seq[byte]) =
  ## Prints the construction line with the recipe read back from the
  ## blob the Pipeline handed out, not echoed from the flags: every
  ## construction override is proven to have reached the library by the
  ## value the receiver would see. Record values that are empty (a No
  ## MAC profile's MAC, a mixed profile's single hash) print as "-".
  var record: Profile
  try:
    record = inspect(blob)
  except ItbError as e:
    logLine("pipeline initialised: profile=" & profileName & " blob=" &
            $blob.len & " bytes (inspect: " & e.lastError & ")")
    return
  var line = "pipeline initialised: profile=" & profileName & " blob=" &
          $blob.len & " bytes hash=" &
          (if record.innerHash.len > 0: record.innerHash else: "-") &
          " key-bits=" & $record.keyBits &
          " nonce-bits=" & $record.nonceBits.get(0) &
          " barrier-fill=" & $record.barrierFill.get(0) &
          " chunk-size=" & $record.chunkSize &
          " mac=" & (if record.macName.len > 0: record.macName else: "-") &
          " parallax=" & onOff(record.parallax) &
          " wrapper=" & onOff(record.wrapper)
  if record.containerMode.get(0) == 2:
    line.add(" container-mode=2")
  if record.drbg.len > 0:
    line.add(" drbg=" & record.drbg)
  logLine(line)

proc editInnerBlobMode(blob: var seq[byte], targetMode: int): bool =
  ## Sets the inner blob's "mode" field of a wrap-layer session blob to
  ## `targetMode` (1 = per-region, 2 = per-container) in place. The wrap
  ## layer's profile record carries its own "mode" (a string), so the
  ## search starts at the inner blob ("ib"); both shipped modes are one
  ## digit wide, so the blob length does not change. Returns false when
  ## the inner blob or its mode field is not found.
  proc find(hay: seq[byte], needle: string, start: int): int =
    for i in start .. hay.len - needle.len:
      var hit = true
      for k in 0 ..< needle.len:
        if hay[i + k] != byte(needle[k]):
          hit = false
          break
      if hit:
        return i
    -1
  const ibKey = "\"ib\":{"
  const modeKey = "\"mode\":"
  let ib = find(blob, ibKey, 0)
  if ib < 0:
    return false
  let mode = find(blob, modeKey, ib + ibKey.len)
  if mode < 0:
    return false
  let at = mode + modeKey.len
  if at + 1 >= blob.len or blob[at] < byte('1') or blob[at] > byte('2') or
      (blob[at + 1] >= byte('0') and blob[at + 1] <= byte('9')):
    return false
  blob[at] = byte(ord('0') + targetMode)
  true

proc buildPipeline(cfg: Config, profileName: string, pipe: var Pipeline,
                   present: var bool, blob: var seq[byte]): bool =
  ## Constructs one Pipeline against `profile` with every flag-carried
  ## override in the opts string (zero values included — the shared
  ## library treats zero as "profile default"), then obtains the Init
  ## blob once through save: the binding's init entry does not hand the
  ## blob back, and the bytes are the ones Init produced. Later blob
  ## reopens use the retained blob; save is never called again.
  var opts = Opts()
    .withInnerHash(cfg.hash)
    .withMacName(cfg.mac)
    .withParallax(cfg.parallax)
    .withWrapper(cfg.wrapper)
    .withKeyBits(cfg.keyBits)
    .withNonceBits(cfg.nonceBits)
    .withBarrierFill(cfg.barrierFill)
    .withDrbg(cfg.drbg)
    .withChunkSize(int(cfg.chunkSize))
  if cfg.profile.len > 0:
    let filled = fillKeystreamLayers(cfg.profile, opts, cfg.parallax, cfg.wrapper)
    if filled < 0:
      return false
    if filled > 0:
      errLine(cfg.profile & " leaves the requested keystream layers unnamed; " &
              KeystreamFillCipher & " supplied for them")

  try:
    pipe = initPipeline(profileName, opts)
  except ItbError as e:
    errLine("Init(" & profileName & "): " & detail(e))
    return false
  present = true
  try:
    blob = pipe.save()
  except ItbError as e:
    errLine("Save(" & profileName & "): " & detail(e))
    return false
  if cfg.blobMode == 2:
    # The sizing mode is not an Opts knob: the Init blob is edited and
    # the pipeline reopened from it, so the retained blob (the one
    # blob-cycle reopens from) carries the edited mode.
    if not editInnerBlobMode(blob, 2):
      errLine("rewrite blob mode: inner blob mode field not found")
      return false
    var fresh: Pipeline
    try:
      fresh = loadPipeline(blob)
    except ItbError as e:
      errLine("reload Mode 2 blob: " & detail(e))
      return false
    pipe.free()
    pipe = fresh
  logPipelineInitialised(profileName, blob)
  true

# ─── Run ───────────────────────────────────────────────────────────

var runState: RunState
  ## Nim-specific. The run state lives at module scope so the address
  ## handed to each worker thread is stable for the whole run; every
  ## worker reaches it through that pointer and never through the
  ## global name, which is what keeps the thread bodies free of the
  ## shared-global access the compiler rejects.

proc run(argv: seq[string]): int =
  cSignal(SIGPIPE, cast[pointer](0))  # SIG_DFL; see cSignal
  let r = addr runState
  let cfg = addr r.cfg
  let rc = parseFlags(argv, cfg[])
  if rc == 1:
    return 0
  if rc != 0:
    return 2

  # Runtime shaping. A long run under allocation churn grows the Go
  # heap inside the shared library without bound unless a soft limit
  # paces the collector, so a limit is always in force: an explicit
  # --memlimit is set as given, and auto caps the heap only when the
  # runtime reports no limit at all (a limit already installed from the
  # environment is left standing). The GC percentage and GOMAXPROCS are
  # set only when their flag is non-zero — a zero flag skips the setter
  # rather than calling it with zero, because zero is a real value to
  # the GC-percent setter, and a call would clobber whatever the
  # environment installed. All of it lands before any Pipeline exists
  # so the baselines are taken under the shaped runtime.
  if cfg.memlimitAuto:
    if setMemoryLimit(-1) == high(int64):
      discard setMemoryLimit(cfg.memlimit)
  else:
    discard setMemoryLimit(cfg.memlimit)
  cfg.memlimit = setMemoryLimit(-1)
  if cfg.gogc > 0:
    discard setGcPercent(cfg.gogc)
  if cfg.gomaxprocs > 0:
    discard setGomaxprocs(cfg.gomaxprocs)

  logLine("start: duration=" & humanDuration(cfg.durationNs) &
          " iterations=" & $cfg.iterations &
          " goroutines=" & $cfg.workersRequested &
          " workers=" & $cfg.workers &
          " concurrency=" & ConcurrencyMode &
          " shape=" & shapeName(cfg.shape) &
          " hash=" & cfg.hash & " mac=" & cfg.mac &
          " payload=" & humanBytes(cfg.payload) &
          " memlimit=" & humanBytes(cfg.memlimit) &
          " parallax=" & onOff(cfg.parallax) &
          " wrapper=" & onOff(cfg.wrapper))
  logLine("overrides: profile=\"" & cfg.profile & "\"" &
          " key-bits=" & $cfg.keyBits &
          " nonce-bits=" & $cfg.nonceBits &
          " chunk-size=" & humanBytes(cfg.chunkSize) &
          " barrier-fill=" & $cfg.barrierFill &
          " gomaxprocs=" & $cfg.gomaxprocs &
          " rekey-every=" & $cfg.rekeyEvery &
          " blob-cycle-every=" & $cfg.blobCycleEvery &
          " payload-mode=" & payloadModeName(cfg.payloadMode) &
          " seed=" & $cfg.seed &
          " json-output=" & (if cfg.jsonOutput: "true" else: "false") &
          (if cfg.blobMode != 1: " blob-mode=" & $cfg.blobMode else: "") &
          (if cfg.drbg.len > 0: " drbg=" & cfg.drbg else: ""))
  logLine("policy: microbatch-tiers=" & policyLabel("ITB_MICROBATCH_TIERS") &
          " hashpool-starters=" & policyLabel("ITB_HASHPOOL_STARTERS"))

  # Pipeline construction — one shared handle per exercised shape.
  # stream and stream_one_shot share the streaming handle.
  r.streamProfile = if cfg.profile.len > 0: cfg.profile else: DefaultStreamProfile
  r.msgProfile = if cfg.profile.len > 0: cfg.profile else: DefaultMessageProfile
  if cfg.shape in {shStream, shStreamOneShot, shBoth}:
    if not buildPipeline(cfg[], r.streamProfile, r.streamPipe, r.hasStream,
                         r.streamBlob):
      return 1
  if cfg.shape in {shMessage, shBoth}:
    if not buildPipeline(cfg[], r.msgProfile, r.msgPipe, r.hasMsg, r.msgBlob):
      return 1

  # Allocation posture. Per-worker plaintexts are allocated once and
  # held for the whole run (rotating mode refills them in place per
  # iteration); the pump accumulators and the drain slice live inside
  # each worker and are reused across iterations; the message and
  # one-shot outputs are handed back per call and released at the end
  # of the iteration. Under the default fixed CSPRNG mode every
  # worker's buffer is distinct, so cross-worker data crossover is
  # detectable; pattern modes trade that property for content
  # edge-case coverage.
  r.workers = newSeq[Worker](cfg.workers)
  for i in 0 ..< cfg.workers:
    let w = addr r.workers[i]
    w.id = i
    w.run = r
    let payloadBytes = int(cfg.payload)
    w.plaintext = newSeq[byte](payloadBytes)
    # The wire accumulator is sized to the encrypt-side envelope
    # (payload plus expansion and framing) and the round-trip one to
    # the plaintext, so the pump refills them in place instead of
    # growing them inside an iteration.
    w.wire = newSeq[byte](payloadBytes + payloadBytes div 4 + 131_072)
    w.plain = newSeq[byte](payloadBytes)
    w.scratch = newSeq[byte](PumpSlice)
    w.payloadMode = cfg.payloadMode
    w.seeded = cfg.seed != 0
    w.rng = seedWorker(cfg.seed, i)
    if not fillPayload(cfg.payloadMode, w.seeded, w.rng, w.plaintext):
      errLine("payload fill: csprng")
      return 1

  if not poolSnapshotAlloc(r.poolWarmup) or not poolSnapshotAlloc(r.poolSteady):
    errLine("pool snapshot alloc failed")
    return 1

  installSignals()
  initRwLock(r.pipeLock)
  initBarrier(r.warmupDone, cfg.workers + 1)
  initBarrier(r.release, cfg.workers + 1)
  r.stop.store(false)
  r.active.store(cfg.workers)

  # Warmup barrier. Every worker runs one iteration and waits; the
  # clock starts only once all of them have paid their first-call costs
  # (pool warm-up, lazy kernel dispatch, page faults on the payload
  # buffers), and the RSS and pool baselines taken here describe a
  # process that has already run the whole cipher path once per worker.
  let warmupStart = nowNs()
  var threads = newSeq[Thread[ptr Worker]](cfg.workers)
  for i in 0 ..< cfg.workers:
    createThread(threads[i], workerMain, addr r.workers[i])
  wait(r.warmupDone)
  readRss(r.rssWarmup, r.rssPeak)
  discard poolSnapshotTake(r.poolWarmup)
  let warmupNs = nowNs() - warmupStart
  logLine("warmup: " & $cfg.workers & " workers x 1 iter completed in " &
          humanDuration((warmupNs + 50_000_000) div 100_000_000 * 100_000_000) &
          " (baseline rss=" & humanBytes(int64(r.rssWarmup)) & ")")

  # Open the gate; the duration timer is a deadline the waiter below
  # enforces in duration mode.
  r.startNs = nowNs()
  r.finishNs = r.startNs
  wait(r.release)

  # Wait for every worker, polling so the deadline and a signal are
  # both noticed promptly. The last worker to return stamps the finish
  # instant itself, so the poll interval never enters the elapsed time.
  while r.active.load() > 0:
    if signalSeen != 0:
      r.stop.store(true)
    if cfg.iterations == 0 and nowNs() - r.startNs >= cfg.durationNs:
      r.stop.store(true)
    sleep(10)
  joinThreads(threads)
  let elapsedNs = r.finishNs - r.startNs
  readRss(r.rssFinal, r.rssPeak)
  discard poolSnapshotTake(r.poolSteady)

  if cfg.memprofile.len > 0:
    try:
      writeHeapProfile(cfg.memprofile)
      logLine("memprofile: heap profile written to " & cfg.memprofile)
    except ItbError as e:
      errLine("memprofile: " & e.lastError)

  finalSummary(r, elapsedNs)

when isMainModule:
  quit(run(commandLineParams()))
