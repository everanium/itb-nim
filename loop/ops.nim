## The maintenance operations that mutate a live Pipeline handle
## between iterations: master rotation (--rekey-every) and blob reopen
## (--blob-cycle-every).

import std/atomics

import ../src/itb3

import ./payload
import ./state

const RekeyMasterSize = 32
  ## Byte length of each fresh master drawn for a rotation. Matches the
  ## size Init auto-generates for both the parallax and the wrapper
  ## master.

proc rekeyPipes(w: ptr Worker, iter: int64): bool =
  ## Master rotation. Rotates the parallax + wrapper masters on every
  ## active Pipeline under the write lock and retains the refreshed
  ## blob for subsequent blob reopens. Masters are drawn fresh from the
  ## OS CSPRNG on every rotation regardless of --seed (master rotation
  ## is pipeline keying, not plaintext content); a disabled layer
  ## passes no bytes, which Rekey ignores. The eight inner seeds and
  ## the MAC key are untouched by design — Rekey targets only the two
  ## outer-layer master secrets.
  let r = w.run
  var perm = newSeq[byte](RekeyMasterSize)
  var wrap = newSeq[byte](RekeyMasterSize)
  var permView: seq[byte]
  var wrapView: seq[byte]

  if r.cfg.parallax:
    if not fillRandom(perm):
      workerFail(w, "g" & $w.id & " iter " & $iter & ": csprng: parallax master")
      return false
    permView = perm
  if r.cfg.wrapper:
    if not fillRandom(wrap):
      workerFail(w, "g" & $w.id & " iter " & $iter & ": csprng: wrapper master")
      return false
    wrapView = wrap

  writeLock(r.pipeLock)
  defer: writeUnlock(r.pipeLock)
  if r.hasStream:
    try:
      r.streamBlob = r.streamPipe.rekey(permView, wrapView)
    except ItbError as e:
      workerFail(w, "g" & $w.id & " iter " & $iter & ": Rekey(" &
                 r.streamProfile & "): " & detail(e))
      return false
  if r.hasMsg:
    try:
      r.msgBlob = r.msgPipe.rekey(permView, wrapView)
    except ItbError as e:
      workerFail(w, "g" & $w.id & " iter " & $iter & ": Rekey(" &
                 r.msgProfile & "): " & detail(e))
      return false
  let n = r.rekeys.fetchAdd(1) + 1
  logLine("rekey: g" & $w.id & " iter " & $iter &
          " rotated parallax + wrapper masters (rekey #" & $n & ")")
  true

proc blobCyclePipes(w: ptr Worker, iter: int64): bool =
  ## Blob reopen. Reopens every active Pipeline from its retained blob
  ## under the write lock: a fresh handle is loaded from the blob, the
  ## running handle is freed, and the fresh one is swapped in, so every
  ## later iteration round-trips through seeds and masters that
  ## survived a blob crossing. The input is the blob Init or the latest
  ## Rekey handed out, not a fresh Save: that is what a receiver holds,
  ## and reopening from it proves the handed-out bytes rather than the
  ## live state. The blob carries the Pipeline's full shape, so no
  ## override reaches the reopen. On a Load failure the running handle
  ## stays and the failure aborts the run.
  let r = w.run
  writeLock(r.pipeLock)
  defer: writeUnlock(r.pipeLock)
  if r.hasStream:
    var fresh: Pipeline
    try:
      # Nim-specific. The fresh handle is constructed into a local
      # first, so a raising Load leaves the running one in place; the
      # assignment then releases the old handle through its destructor.
      fresh = loadPipeline(r.streamBlob)
    except ItbError as e:
      workerFail(w, "g" & $w.id & " iter " & $iter & ": Load(" &
                 r.streamProfile & "): " & detail(e))
      return false
    r.streamPipe.free()
    r.streamPipe = fresh
  if r.hasMsg:
    var fresh: Pipeline
    try:
      fresh = loadPipeline(r.msgBlob)
    except ItbError as e:
      workerFail(w, "g" & $w.id & " iter " & $iter & ": Load(" &
                 r.msgProfile & "): " & detail(e))
      return false
    r.msgPipe.free()
    r.msgPipe = fresh
  let n = r.blobCycles.fetchAdd(1) + 1
  logLine("blob-cycle: g" & $w.id & " iter " & $iter &
          " reopened from session blob (cycle #" & $n & ")")
  true

proc workerMaintenance*(w: ptr Worker, iter: int64): bool =
  ## Handle mutation. Runs the periodic Pipeline-mutating operations
  ## after a completed iteration: master rotation (--rekey-every) and
  ## blob reopen (--blob-cycle-every). Both intervals count per-worker
  ## iterations; the warmup iteration (iter 0) never triggers because
  ## the worker loop calls this for iter >= 1 only. Rekey rewrites the
  ## outer-layer keying of a live handle and a blob reopen replaces the
  ## handle outright; each takes the write lock, so in-flight cipher
  ## calls on other workers drain before anything changes and no
  ## encrypt is separated from its decrypt by either. Returns false
  ## after recording the worker error.
  let cfg = addr w.run.cfg
  if cfg.rekeyEvery > 0 and iter mod cfg.rekeyEvery == 0:
    if not rekeyPipes(w, iter):
      return false
  if cfg.blobCycleEvery > 0 and iter mod cfg.blobCycleEvery == 0:
    if not blobCyclePipes(w, iter):
      return false
  true
