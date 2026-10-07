## Process-wide Go runtime knobs and the library version string.

import ./errors
import ./ffi_bridge

proc setMemoryLimit*(limitBytes: int64): int64 =
  ## Sets the Go runtime's soft heap limit in bytes and returns the
  ## previous limit. A negative value queries without changing.
  ITB_SetMemoryLimit(limitBytes)

proc setGcPercent*(pct: int): int =
  ## Sets the Go GC trigger percentage and returns the previous
  ## value. A negative value queries without changing.
  int(ITB_SetGCPercent(cint(pct)))

proc version*(): string =
  ## Returns the libitb3 library version string.
  var need: csize_t = 0
  let rc = int(ITB_Version(nil, 0, addr need))
  if rc notin {ord(stOk), ord(stBufferTooSmall)}:
    raise newItbError(statusFrom(rc), rc, lastErrorText())
  if int(need) <= 1:
    return ""
  var buf = newString(int(need))
  check(ITB_Version(addr buf[0], csize_t(buf.len), addr need))
  buf.setLen(max(int(need) - 1, 0))
  buf

proc drbgAutoTier*(): string =
  ## Returns the fill cipher the auto DRBG tier selected on this host
  ## (``"aes-256-ctr"`` or ``"chacha20"``): the tier a Pipeline uses
  ## when its drbg option is empty, resolved per host and recorded in
  ## no blob.
  var need: csize_t = 0
  let rc = int(ITB_DRBGAutoTier(nil, 0, addr need))
  if rc notin {ord(stOk), ord(stBufferTooSmall)}:
    raise newItbError(statusFrom(rc), rc, lastErrorText())
  if int(need) <= 1:
    return ""
  var buf = newString(int(need))
  check(ITB_DRBGAutoTier(addr buf[0], csize_t(buf.len), addr need))
  buf.setLen(max(int(need) - 1, 0))
  buf

proc setGomaxprocs*(n: int): int =
  ## Sets the Go runtime's GOMAXPROCS and returns the previous value.
  ## Zero or a negative value queries without changing.
  int(ITB_SetGOMAXPROCS(cint(n)))

proc writeHeapProfile*(path: string) =
  ## Writes the Go runtime's heap profile (pprof format) to ``path``
  ## after one forced garbage collection. An empty path falls back to
  ## the ``ITB_MEMPROFILE`` environment variable; a path that is still
  ## empty, or a file-system failure, raises ``ItbError`` carrying
  ## ``stBadInput`` and the diagnostic.
  check(ITB_WriteHeapProfile(path.cstring))

proc poolStatsLen*(): int =
  ## Number of ``int64`` slots ``poolStats`` fills. Size the
  ## destination from this call, never from a constant.
  let n = int(ITB_PoolStatsLen())
  if n > 0: n else: 0

proc poolStats*(dst: var openArray[int64]): int =
  ## Copies the library's pool hit / miss counters into ``dst`` and
  ## returns the slot count written. Every counter is a monotonically
  ## increasing total since library load; difference two snapshots.
  ## Slot layout, with ``T`` the tier count in slot 0: tier ``i`` holds
  ## starter width, checkouts, constructor misses, regrow replacements
  ## and bytes allocated at slots ``1 + 5*i .. 1 + 5*i + 4``; the
  ## scratch byte pool's get / new / regrow / regrow-bytes follow at
  ## ``1 + 5*T``, and the parallax chunk pool's at ``1 + 5*T + 4``. A
  ## ``dst`` shorter than ``poolStatsLen`` raises ``ItbError`` with
  ## ``stBufferTooSmall``.
  var written: csize_t = 0
  let p = if dst.len > 0: addr dst[0] else: nil
  check(ITB_PoolStats(p, csize_t(dst.len), addr written))
  int(written)
