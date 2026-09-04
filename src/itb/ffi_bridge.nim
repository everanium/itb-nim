## Runtime symbol binding over the libitb shared library.
##
## Every ``ITB_*`` entry point used by the binding is declared with
## ``{.importc, cdecl, dynlib.}`` against a search path computed at
## program start. Search order:
##
## 1. ``ITB_LIBITB_PATH`` environment variable (path to the shared
##    library file).
## 2. ``<repo>/dist/<os>-<arch>/libitb.<ext>`` resolved by walking up
##    from the executable's directory (in-repo builds).
## 3. The OS default loader path (``LD_LIBRARY_PATH``,
##    ``ld.so.cache``, ``DYLD_LIBRARY_PATH``, ``PATH``).
##
## A resolve failure surfaces as the Nim runtime's
## ``could not load: libitb.so`` diagnostic at program start.
##
## Every prototype mirrors ``cmd/cshared``'s generated ``libitb.h``;
## ``uintptr_t`` handles cross as ``csize_t`` (same width on every
## supported platform).

import std/[os]
import ./errors

const
  LibFilename =
    when defined(windows): "libitb.dll"
    elif defined(macosx): "libitb.dylib"
    else: "libitb.so"
  DistSubdir =
    (when defined(windows): "windows"
     elif defined(macosx): "darwin"
     else: "linux") & "-" & hostCPU

var cachedLibPath = ""

proc itbLibPath*(): string =
  ## Resolves the shared-library path once per process (see the
  ## module docstring for the search order).
  if cachedLibPath.len > 0:
    return cachedLibPath
  let env = getEnv("ITB_LIBITB_PATH")
  if env.len > 0:
    cachedLibPath = env
    return cachedLibPath
  var dir = getAppDir()
  for _ in 0 ..< 16:
    let cand = dir / "dist" / DistSubdir / LibFilename
    if fileExists(cand):
      cachedLibPath = cand
      return cachedLibPath
    let parent = parentDir(dir)
    if parent.len == 0 or parent == dir:
      break
    dir = parent
  cachedLibPath = LibFilename
  cachedLibPath

{.push cdecl, importc, dynlib: itbLibPath().}

proc ITB_Version*(outBuf: pointer, capBytes: csize_t,
                  outLen: ptr csize_t): cint
proc ITB_LastError*(outBuf: pointer, capBytes: csize_t,
                    outLen: ptr csize_t): cint
proc ITB_SetMemoryLimit*(limit: int64): int64
proc ITB_SetGCPercent*(pct: cint): cint

proc ITB_Triple_Init*(profile: cstring, opts: cstring, blobOut: pointer,
                      blobCap: csize_t, blobLen: ptr csize_t,
                      outHandle: ptr csize_t): cint
proc ITB_Triple_Load*(blob: pointer, blobLen: csize_t,
                      permMaster: pointer, permMasterLen: csize_t,
                      wrapMaster: pointer, wrapMasterLen: csize_t,
                      mastersCount: csize_t, outHandle: ptr csize_t): cint
proc ITB_Triple_LoadF*(path: cstring,
                       permMaster: pointer, permMasterLen: csize_t,
                       wrapMaster: pointer, wrapMasterLen: csize_t,
                       mastersCount: csize_t, outHandle: ptr csize_t): cint
proc ITB_Triple_Save*(handle: csize_t, blobOut: pointer, blobCap: csize_t,
                      blobLen: ptr csize_t): cint
proc ITB_Triple_SaveF*(handle: csize_t, path: cstring): cint
proc ITB_Triple_Inspect*(blob: pointer, blobLen: csize_t, jsonOut: pointer,
                         jsonCap: csize_t, jsonLen: ptr csize_t): cint
proc ITB_Triple_MaxWorkers*(handle: csize_t, n: cint): cint
proc ITB_Triple_Rekey*(handle: csize_t, permMaster: pointer,
                       permMasterLen: csize_t, wrapMaster: pointer,
                       wrapMasterLen: csize_t, blobOut: pointer,
                       blobCap: csize_t, blobLen: ptr csize_t): cint
proc ITB_Triple_Close*(handle: csize_t): cint
proc ITB_Triple_Free*(handle: csize_t): cint
proc ITB_Triple_EncryptStream*(handle: csize_t, plaintext: pointer,
                               ptlen: csize_t, outBuf: pointer,
                               outCap: csize_t, outLen: ptr csize_t): cint
proc ITB_Triple_DecryptStream*(handle: csize_t, wire: pointer,
                               wireLen: csize_t, outBuf: pointer,
                               outCap: csize_t, outLen: ptr csize_t): cint
proc ITB_Triple_EncryptMessage*(handle: csize_t, plaintext: pointer,
                                ptlen: csize_t, outBuf: pointer,
                                outCap: csize_t, outLen: ptr csize_t): cint
proc ITB_Triple_DecryptMessage*(handle: csize_t, wire: pointer,
                                wireLen: csize_t, outBuf: pointer,
                                outCap: csize_t, outLen: ptr csize_t): cint
proc ITB_Triple_Register*(name: cstring, profileJson: cstring): cint
proc ITB_Triple_Lookup*(name: cstring, jsonOut: pointer, jsonCap: csize_t,
                        jsonLen: ptr csize_t): cint
proc ITB_Triple_Profiles*(jsonOut: pointer, jsonCap: csize_t,
                          jsonLen: ptr csize_t): cint
proc ITB_Triple_EncryptStreamBegin*(pipe: csize_t,
                                    outStream: ptr csize_t): cint
proc ITB_Triple_DecryptStreamBegin*(pipe: csize_t,
                                    outStream: ptr csize_t): cint
proc ITB_Triple_StreamWrite*(stream: csize_t, src: pointer,
                             srcLen: csize_t): cint
proc ITB_Triple_StreamEnd*(stream: csize_t): cint
proc ITB_Triple_StreamRead*(stream: csize_t, outBuf: pointer,
                            outCap: csize_t, outLen: ptr csize_t,
                            finished: ptr cint): cint
proc ITB_Triple_StreamFree*(stream: csize_t): cint

{.pop.}

proc lastErrorText*(): string =
  ## Reads the ``ITB_LastError`` diagnostic (NUL-stripped). Returns
  ## the empty string when no diagnostic is recorded.
  var need: csize_t = 0
  let rc = int(ITB_LastError(nil, 0, addr need))
  if rc notin {ord(stOk), ord(stBufferTooSmall)} or int(need) <= 1:
    return ""
  var buf = newString(int(need))
  if int(ITB_LastError(addr buf[0], csize_t(buf.len), addr need)) != ord(stOk):
    return ""
  buf.setLen(max(int(need) - 1, 0))
  buf

proc check*(rc: cint) =
  ## Maps a raw FFI return code onto ``void`` / raised ``ItbError``.
  if int(rc) == ord(stOk):
    return
  raise newItbError(statusFrom(int(rc)), int(rc), lastErrorText())

func toPtr*(data: openArray[byte]): pointer =
  ## Borrowed input pointer with the empty-array guard (indexing an
  ## empty ``openArray`` is a defect even for address-of).
  if data.len > 0: cast[pointer](unsafeAddr data[0]) else: nil
