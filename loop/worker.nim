## The worker: its thread body (one warmup iteration, the warmup
## barrier, the main loop), one iteration, the session pump loop the
## stream shape drives, and the round-trip comparison that decides
## between a worker error and a data mismatch.

import std/[atomics, strutils]

import ../src/itb3

import ./ops
import ./payload
import ./size
import ./state

proc cExit(code: cint) {.importc: "_exit", header: "<unistd.h>", noreturn.}
  ## Nim-specific. `quit` unwinds through the exit hooks and the
  ## destructors of every live global; the data-mismatch path must not
  ## run any of that, so the raw process-termination entry is declared
  ## here and the evidence line is flushed before it is called.

const shapeNames = ["stream", "message", "stream_one_shot", "both"]

proc shapeName*(shape: Shape): string =
  shapeNames[ord(shape)]

proc parseShape*(s: string, outShape: var Shape): bool =
  for i, name in shapeNames:
    if s == name:
      outShape = Shape(i)
      return true
  false

proc firstDifference(a: openArray[byte], b: openArray[byte]): int =
  ## First offset at which `a` and `b` differ; the shorter length when
  ## one is a prefix of the other.
  let n = min(a.len, b.len)
  for i in 0 ..< n:
    if a[i] != b[i]:
      return i
  n

proc hexWindow(buf: openArray[byte], off: int): string =
  ## Up to 16 bytes of `buf` from `off` as lowercase hex, or "-" when
  ## `buf` has no bytes there.
  if off >= buf.len:
    return "-"
  let last = min(off + 16, buf.len) - 1
  for i in off .. last:
    result.add(toHex(buf[i].int, 2).toLowerAscii())

proc cipherFail(w: ptr Worker, iter: int64, shape: Shape, direction: string,
                stage: string, e: ref ItbError) =
  ## Records a worker error for a failed cipher call. `stage` names the
  ## session step for a pump failure and is empty for a whole-buffer
  ## call, whose only step is the direction itself.
  if stage.len == 0 or stage == direction:
    workerFail(w, "g" & $w.id & " iter " & $iter & " shape=" & shapeName(shape) &
               ": " & direction & ": " & detail(e))
  else:
    workerFail(w, "g" & $w.id & " iter " & $iter & " shape=" & shapeName(shape) &
               ": " & direction & ": " & stage & ": " & detail(e))

proc pumpBody(w: ptr Worker, session: StreamSession, src: openArray[byte],
              acc: var seq[byte], used: var int, stage: var string) =
  ## Pump loop. The Go harness hands ITB an io.Reader / io.Writer pair
  ## and ITB drives the chunk loop internally; the C ABI has no reader
  ## / writer entry, so the caller drives it: open a session, feed
  ## slices of at most 1 MiB, drain whatever the session has produced
  ## after every write (a read before end never blocks), end, then
  ## drain until the session reports finished (after end, a read on an
  ## empty spool blocks until the terminal bytes arrive). The whole
  ## produced output lands in the worker's reusable accumulator. The
  ## loop is written here rather than delegated to the binding's pump
  ## convenience so it stands in the utility, at the same place, in
  ## every language.
  proc put(acc: var seq[byte], used: var int, src: openArray[byte]) =
    if used + src.len > acc.len:
      acc.setLen(used + src.len)
    if src.len > 0:
      copyMem(addr acc[used], unsafeAddr src[0], src.len)
    used += src.len

  var off = 0
  while off < src.len:
    let hi = min(off + PumpSlice, src.len)
    stage = "StreamWrite"
    session.write(src.toOpenArray(off, hi - 1))
    off = hi
    while true:
      stage = "StreamRead"
      let (n, _) = session.readInto(w.scratch)
      if n == 0:
        break
      put(acc, used, w.scratch.toOpenArray(0, n - 1))
  stage = "StreamEnd"
  session.endStream()
  while true:
    stage = "StreamRead"
    let (n, finished) = session.readInto(w.scratch)
    if n > 0:
      put(acc, used, w.scratch.toOpenArray(0, n - 1))
    if finished:
      return

proc pump(w: ptr Worker, pipe: Pipeline, encrypt: bool, src: openArray[byte],
          acc: var seq[byte], used: var int,
          stage: var string): ref ItbError =
  ## Runs one direction of the pump against the streaming Pipeline.
  ## Returns nil on success, or the exception the failing step raised
  ## with that step's name left in `stage`.
  used = 0
  var session: StreamSession
  try:
    stage = "StreamBegin"
    session = if encrypt: StreamSession(pipe.encryptStream())
              else: StreamSession(pipe.decryptStream())
    pumpBody(w, session, src, acc, used, stage)
  except ItbError as e:
    if session != nil:
      session.free()
    return e
  session.free()
  nil

proc iterate(w: ptr Worker, iter: int64): bool =
  ## One iteration. In order: refill the plaintext under rotating mode;
  ## take the read lock; pick the surface; encrypt (timed); decrypt
  ## (timed); compare the round-trip with the plaintext; bump the
  ## counters; release the lock. The whole round-trip runs under the
  ## read lock so handle-mutating maintenance (rekey, blob reopen)
  ## never lands between an encrypt and its matching decrypt —
  ## maintenance runs after this returns, from the worker loop.
  let r = w.run

  if w.payloadMode == pmRotating:
    if not fillPayload(pmRotating, w.seeded, w.rng, w.plaintext):
      workerFail(w, "g" & $w.id & " iter " & $iter & ": payload refill: csprng")
      return false

  readLock(r.pipeLock)
  defer: readUnlock(r.pipeLock)

  # Shape dispatch. message is one whole-buffer call on the Single
  # Message Pipeline; stream_one_shot is one whole-buffer call on the
  # streaming Pipeline (the C ABI's ITB_Triple_EncryptStream, which
  # routes to the same one-shot stream entry the Go harness calls
  # by name); stream opens a session on the same streaming Pipeline and
  # drives the chunk loop from here. Under both the three rotate by
  # iteration number so the session path and the whole-buffer path
  # alternate on one handle inside every worker — the cross-path
  # state-reuse hazard this harness exists to catch.
  var shape = r.cfg.shape
  if shape == shBoth:
    case iter mod 3
    of 0: shape = shStream
    of 1: shape = shMessage
    else: shape = shStreamOneShot

  # Nim-specific. The message and one-shot entries hand back a fresh
  # seq per call, reclaimed when the iteration's locals leave scope;
  # the pump accumulators are the worker's own and are reused. Both
  # owners are declared here so either path's output outlives the
  # comparison below.
  var ownedWire: seq[byte]
  var ownedPlain: seq[byte]
  var gotLen = 0
  var fromPump = false
  var stage = ""
  var t0: int64

  case shape
  of shStream:
    fromPump = true
    t0 = nowNs()
    let e1 = pump(w, r.streamPipe, true, w.plaintext, w.wire, w.wireLen, stage)
    if e1 != nil:
      cipherFail(w, iter, shape, "encrypt", stage, e1)
      return false
    w.nanosEnc += nowNs() - t0
    t0 = nowNs()
    let e2 = pump(w, r.streamPipe, false,
                  w.wire.toOpenArray(0, w.wireLen - 1),
                  w.plain, w.plainLen, stage)
    if e2 != nil:
      cipherFail(w, iter, shape, "decrypt", stage, e2)
      return false
    w.nanosDec += nowNs() - t0
    gotLen = w.plainLen
  of shStreamOneShot:
    try:
      t0 = nowNs()
      ownedWire = r.streamPipe.encryptStreamOneShot(w.plaintext)
      w.nanosEnc += nowNs() - t0
    except ItbError as e:
      cipherFail(w, iter, shape, "encrypt", "", e)
      return false
    try:
      t0 = nowNs()
      ownedPlain = r.streamPipe.decryptStreamOneShot(ownedWire)
      w.nanosDec += nowNs() - t0
    except ItbError as e:
      cipherFail(w, iter, shape, "decrypt", "", e)
      return false
    gotLen = ownedPlain.len
  of shMessage:
    try:
      t0 = nowNs()
      ownedWire = r.msgPipe.encryptMessage(w.plaintext)
      w.nanosEnc += nowNs() - t0
    except ItbError as e:
      cipherFail(w, iter, shape, "encrypt", "", e)
      return false
    try:
      t0 = nowNs()
      ownedPlain = r.msgPipe.decryptMessage(ownedWire)
      w.nanosDec += nowNs() - t0
    except ItbError as e:
      cipherFail(w, iter, shape, "decrypt", "", e)
      return false
    gotLen = ownedPlain.len
  of shBoth:
    discard # resolved above

  # Failure model. A cipher call that returns a non-OK status is a
  # worker error: it is recorded, the run is asked to stop, the other
  # workers finish their in-flight iteration, and the error is listed
  # in the summary with the FAIL verdict. A round-trip that returns OK
  # with different bytes is a data mismatch: the process terminates
  # here, without summary or cleanup, because the Pipeline state that
  # produced the wrong bytes is the evidence and nothing that runs
  # afterwards may touch it.
  block compare:
    template got(): untyped =
      (if fromPump: w.plain.toOpenArray(0, gotLen - 1)
       else: ownedPlain.toOpenArray(0, gotLen - 1))
    var same = gotLen == w.plaintext.len
    if same and gotLen > 0:
      same = equalMem(unsafeAddr w.plaintext[0],
                      (if fromPump: unsafeAddr w.plain[0]
                       else: unsafeAddr ownedPlain[0]), gotLen)
    if same:
      break compare
    let off = firstDifference(w.plaintext, got())
    errLine("DATA MISMATCH g" & $w.id & " iter " & $iter & " shape=" &
            shapeName(shape) & ": want " & $w.plaintext.len & " bytes, got " &
            $gotLen & " bytes, first difference at offset " & $off &
            ": want " & hexWindow(w.plaintext, off) & " got " &
            hexWindow(got(), off))
    cExit(3)

  w.iters += 1
  w.bytesEnc += int64(w.plaintext.len)
  w.bytesDec += int64(gotLen)
  true

proc workerDone(r: ptr RunState) =
  ## Marks this worker returned; the last one to return stamps the
  ## finish instant.
  if r.active.fetchSub(1) == 1:
    r.finishNs = nowNs()

proc workerMain*(wp: ptr Worker) {.thread.} =
  ## The worker thread body: one warmup iteration, the warmup barrier,
  ## then the main loop until a stop is requested or the fixed
  ## per-worker iteration budget (warmup included) is spent. A failing
  ## warmup still passes both barriers so the launcher never waits on a
  ## worker that has already given up.
  ##
  ## Concurrency mode. This binding runs shared-handle: worker threads
  ## call into one Pipeline handle concurrently, which the shared
  ## library permits once the handle is constructed, so --goroutines is
  ## the thread count verbatim, never clamped.
  ##
  ## Nim-specific. The compiler cannot see through the binding's
  ## indirect dispatch to its FFI entries, so it marks the cipher calls
  ## GC-unsafe; every call they make lands in a C entry that owns no
  ## Nim heap, and the shared state this thread touches is reached
  ## through a `ptr` rather than a global, so the cast asserts what the
  ## call graph already guarantees.
  {.cast(gcsafe).}:
    let w = wp
    let r = w.run

    # Warmup iteration — counted in the totals; its completion feeds
    # the post-warmup baselines.
    let ok = iterate(w, 0)
    wait(r.warmupDone)
    wait(r.release)
    if not ok:
      workerDone(r)
      return

    var iter = 1'i64
    while true:
      if r.cfg.iterations > 0 and iter >= r.cfg.iterations:
        break
      if r.stop.load():
        break
      if not iterate(w, iter):
        break
      if not workerMaintenance(w, iter):
        break
      inc iter
    workerDone(r)
