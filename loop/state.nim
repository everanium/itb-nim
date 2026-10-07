## Shared declarations of the loop stress harness: the vocabulary, the
## resolved configuration, the per-worker state, the run state every
## worker shares, the two synchronisation primitives the run needs, and
## the prefixed output routines every unit writes through.
##
## Nim-specific. Nim modules may not import one another in a cycle, and
## the unit boundaries need `main`, `worker`, `ops` and `summary` to
## name each other's types and to write through one logging routine, so
## the declarations both sides need live in a unit of their own. The
## same unit carries the reader-writer lock and the barrier: neither is
## in the standard library, so both are built here over `std/locks`
## once rather than in each unit that waits on them.

import std/[atomics, locks, os, strutils]

import ../src/itb3

# ─── Vocabulary ────────────────────────────────────────────────────

type
  Shape* = enum
    ## Cipher surfaces the --shape flag selects.
    shStream          ## session pump: begin / write / read / end
    shMessage         ## Single Message: one whole-buffer call
    shStreamOneShot   ## stream surface, one whole-buffer call
    shBoth            ## all three, rotating by iteration number

  PayloadMode* = enum
    ## Plaintext content policies the --payload-mode flag selects.
    pmFixed
    pmRotating
    pmPatternZero
    pmPatternFF
    pmPatternAscii

const
  MaxWorkers* = 10
    ## --goroutines ceiling; the harness targets modest hosts and each
    ## worker pins payload-sized buffers for the whole run.

  ConcurrencyMode* = "shared-handle"
    ## The concurrency mode this binding implements, as the summary
    ## reports it (shared-handle / independent-handles / single).

  PumpSlice* = 1 shl 20
    ## Largest slice fed to a stream session per write; the drain after
    ## every write uses the same bound.

# ─── Configuration ─────────────────────────────────────────────────

type
  Config* = object
    ## The resolved command line.
    durationNs*: int64      ## run duration; ignored when iterations > 0
    iterations*: int64      ## per-worker count incl. warmup; 0 = duration-based
    workersRequested*: int  ## the --goroutines value as given
    workers*: int           ## the effective worker count
    shape*: Shape
    hash*: string
    mac*: string
    payload*: int64         ## bytes per iteration
    memlimit*: int64        ## resolved bytes; the effective limit once shaped
    memlimitAuto*: bool     ## --memlimit auto: cap only when the runtime has no limit
    gogc*: int              ## 0 = leave the runtime default
    parallax*: bool
    wrapper*: bool

    profile*: string        ## empty = shape-based profile pair
    keyBits*: int           ## 0 = profile default
    nonceBits*: int         ## 0 = profile default
    blobMode*: int          ## container floor sizing mode: 1 (per-region, default) | 2 (per-container)
    chunkSize*: int64       ## 0 = profile default
    barrierFill*: int       ## 0 = profile default
    drbg*: string           ## DRBG fill primitive; empty = profile default (auto tier)
    gomaxprocs*: int        ## 0 = inherit from the environment
    rekeyEvery*: int64      ## per-worker iterations between rotations; 0 = never
    blobCycleEvery*: int64  ## per-worker iterations between reopens; 0 = never
    payloadMode*: PayloadMode
    seed*: uint64           ## 0 = OS CSPRNG plaintexts
    jsonOutput*: bool
    memprofile*: string     ## empty = none

# ─── Synchronisation ───────────────────────────────────────────────

type
  RwLock* = object
    ## Nim-specific. The standard library carries a plain lock and a
    ## reentrant one, neither of which distinguishes a reader from a
    ## writer, so the reader-writer lock the run structure calls for is
    ## built here over a lock and a condition variable. A plain mutex
    ## on the read path would serialise every cipher call and hide the
    ## concurrency this utility exists to stress.
    mu: Lock
    cv: Cond
    readers: int
    writer: bool
    waitingWriters: int

  Barrier* = object
    ## Nim-specific. The standard library has no barrier either; this
    ## one is generation-counted so two consecutive waits on the same
    ## barrier cannot be joined by a thread that reaches the second
    ## before a sibling has left the first.
    mu: Lock
    cv: Cond
    parties: int
    count: int
    generation: uint64

proc initRwLock*(l: var RwLock) =
  initLock(l.mu)
  initCond(l.cv)
  l.readers = 0
  l.writer = false
  l.waitingWriters = 0

proc readLock*(l: var RwLock) =
  acquire(l.mu)
  # Waiting writers go first, so a steady stream of readers cannot
  # starve a rekey or a blob reopen.
  while l.writer or l.waitingWriters > 0:
    wait(l.cv, l.mu)
  inc l.readers
  release(l.mu)

proc readUnlock*(l: var RwLock) =
  acquire(l.mu)
  dec l.readers
  if l.readers == 0:
    broadcast(l.cv)
  release(l.mu)

proc writeLock*(l: var RwLock) =
  acquire(l.mu)
  inc l.waitingWriters
  while l.writer or l.readers > 0:
    wait(l.cv, l.mu)
  dec l.waitingWriters
  l.writer = true
  release(l.mu)

proc writeUnlock*(l: var RwLock) =
  acquire(l.mu)
  l.writer = false
  broadcast(l.cv)
  release(l.mu)

proc initBarrier*(b: var Barrier, parties: int) =
  initLock(b.mu)
  initCond(b.cv)
  b.parties = parties
  b.count = 0
  b.generation = 0

proc wait*(b: var Barrier) =
  acquire(b.mu)
  let gen = b.generation
  inc b.count
  if b.count == b.parties:
    b.count = 0
    inc b.generation
    broadcast(b.cv)
  else:
    while gen == b.generation:
      wait(b.cv, b.mu)
  release(b.mu)

# ─── Worker and run state ──────────────────────────────────────────

type
  Worker* = object
    ## One worker's private state: its plaintext, its reusable output
    ## buffers, its generator, its counters, and the error it stopped
    ## on.
    id*: int
    run*: ptr RunState

    plaintext*: seq[byte]
    payloadMode*: PayloadMode
    seeded*: bool
    rng*: uint64            ## splitmix64 state when seeded

    # Nim-specific. The pump accumulators are allocated once at their
    # full working size and refilled in place, with a byte count
    # beside each, rather than grown by append: a `setLen` that grows
    # inside an iteration reallocates and copies while sibling workers
    # are inside a call into the shared library, which is allocation
    # the steady state does not need. The message and one-shot entries
    # hand back a fresh seq per call, which is the posture the binding
    # already takes on its own cipher path.
    wire*: seq[byte]        ## pump-loop wire accumulator
    wireLen*: int           ## bytes currently held in wire
    plain*: seq[byte]       ## pump-loop round-trip accumulator
    plainLen*: int          ## bytes currently held in plain
    scratch*: seq[byte]     ## pump-loop drain slice

    # Counters read by the summary after every worker has returned.
    # Nim-specific. Each is written by its owning worker alone and
    # read only after `joinThreads`, which is the ordering edge, so
    # these need no atomic of their own; the run-wide counters below
    # are incremented by every worker and do.
    iters*: int64
    bytesEnc*: int64
    bytesDec*: int64
    nanosEnc*: int64
    nanosDec*: int64

    failed*: bool
    error*: string

  RunState* = object
    ## The state every worker shares: the Pipeline handles, the
    ## retained blobs, the lock that keeps iterations clear of handle
    ## mutation, the stop request, the barriers, and the baselines the
    ## summary reads.
    cfg*: Config

    streamPipe*: Pipeline   ## live only while hasStream
    msgPipe*: Pipeline      ## live only while hasMsg
    hasStream*: bool
    hasMsg*: bool
    streamProfile*: string
    msgProfile*: string

    # Handle mutation. Iterations hold the read side for their whole
    # encrypt → decrypt → compare; rekey and blob reopen take the
    # write side, so no cipher call is in flight while a handle's
    # keying changes or the handle itself is swapped, and no encrypt
    # is separated from its decrypt by either.
    pipeLock*: RwLock

    # The blob Init handed out, replaced by every rekey; the input of
    # the next blob reopen. Guarded by pipeLock.
    streamBlob*: seq[byte]
    msgBlob*: seq[byte]

    rekeys*: Atomic[int64]
    blobCycles*: Atomic[int64]

    workers*: seq[Worker]

    # Warmup barrier: workers arrive at warmupDone after iteration 0
    # and at release once main has taken the baselines.
    warmupDone*: Barrier
    release*: Barrier

    # Set by the duration deadline, by a signal, or by a failing
    # worker; checked by every worker before it starts an iteration.
    stop*: Atomic[bool]

    # Main waits for active to reach zero; the last returning worker
    # stamps finishNs so elapsed excludes the wake-up latency of the
    # waiter.
    active*: Atomic[int]
    startNs*: int64
    finishNs*: int64

    # Baselines taken after the warmup barrier and at shutdown.
    rssWarmup*: uint64
    rssPeak*: uint64
    rssFinal*: uint64
    poolWarmup*: seq[int64]
    poolSteady*: seq[int64]

# ─── Output ────────────────────────────────────────────────────────

var outMu: Lock
initLock(outMu)

proc logLine*(text: string) =
  ## Prints one prefixed status line to stdout. The text, its prefix
  ## and its newline leave in one write: workers log concurrently
  ## during maintenance, and a routine that emitted them separately
  ## would let another worker's line land between the parts.
  let line = "[loop] " & text & "\n"
  acquire(outMu)
  stdout.write(line)
  stdout.flushFile()
  release(outMu)

proc errLine*(text: string) =
  ## The stderr counterpart, under the same one-write rule.
  let line = "loop: " & text & "\n"
  acquire(outMu)
  stderr.write(line)
  stderr.flushFile()
  release(outMu)

proc errRaw*(text: string) =
  ## Writes text to stderr verbatim, in one call (the usage block).
  acquire(outMu)
  stderr.write(text)
  stderr.flushFile()
  release(outMu)

proc onOff*(b: bool): string =
  if b: "on" else: "off"

proc detail*(e: ref ItbError): string =
  ## Renders a failed library call the way every implementation
  ## reports one: the numeric status the binding's own surface
  ## carries, then the sentence the library left behind.
  ##
  ## Nim-specific. The exception's own message carries the same pair
  ## under a different punctuation, so the two parts are taken from
  ## the binding's own error fields — the status code and the sentence
  ## the binding captured from the library at the moment the call
  ## failed — rather than reshaped from that text.
  "status " & $e.statusCode & ": " & e.lastError

proc policyLabel*(name: string): string =
  ## Renders an encoder policy env value for the summary: the raw
  ## string when set, "default" when the shipped ladder applies.
  if not existsEnv(name):
    return "default"
  var v = getEnv(name)
  var i = 0
  while i < v.len and (v[i] == ' ' or v[i] == '\t'):
    inc i
  v = v[i .. ^1]
  if v.len > 0: v else: "default"

proc workerFail*(w: ptr Worker, text: string) =
  ## Records the worker's error text (first error wins) and requests a
  ## stop of the whole run.
  if not w.failed:
    w.error = text
    w.failed = true
  w.run.stop.store(true)

proc fmtF*(v: float, decimals: int): string =
  ## Nim-specific. The fractional renderings go through the standard
  ## library's fixed-decimal formatter, which composes a C format
  ## specifier and hands the value to the platform's own printf, so
  ## the digits a summary carries are the ones every other
  ## implementation prints.
  formatFloat(v, ffDecimal, decimals)
