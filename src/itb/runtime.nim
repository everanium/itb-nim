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
  ## Returns the libitb library version string.
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
