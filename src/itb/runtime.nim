## Process-wide Go runtime knobs, the library version string, and the
## diagnostic rosters (hash primitives, shipped profile names).

import ./errors
import ./ffi_bridge

type
  HashInfo* = object
    ## One shipped hash primitive: canonical registry name plus the
    ## native state width in bits.
    name*: string
    width*: int

const
  ## The shipped built-in Triple profile names.
  Profiles* = [
    "streaming-aead-triple-mac-v1",
    "streaming-noaead-triple-v1",
    "singlemsg-triple-mac-v1",
    "singlemsg-triple-nomac-v1",
    "blob-triple-mac-v1",
    "streaming-aead-triple-mac-mixed-v1",
    "streaming-noaead-triple-mixed-v1",
    "singlemsg-triple-mac-mixed-v1",
    "singlemsg-triple-nomac-mixed-v1",
  ]

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

proc hashes*(): seq[HashInfo] =
  ## The shipped hash primitive roster in registry order.
  let count = int(ITB_HashCount())
  result = newSeqOfCap[HashInfo](count)
  for i in 0 ..< count:
    var buf = newString(128)
    var need: csize_t = 0
    check(ITB_HashName(cint(i), addr buf[0], csize_t(buf.len), addr need))
    buf.setLen(max(int(need) - 1, 0))
    result.add(HashInfo(name: buf, width: int(ITB_HashWidth(cint(i)))))

func profiles*(): seq[string] =
  ## The shipped Triple profile names.
  @Profiles
