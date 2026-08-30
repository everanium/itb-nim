## Handle-lifetime wrapper around the Triple Pipeline surface.
##
## A ``Pipeline`` is a ``ref`` — un-freed handles are reclaimed by
## ORC via the embedded handle's ``=destroy`` hook; explicit ``free``
## (or ``close``) releases the Go-side state deterministically.

import ./errors
import ./ffi_bridge
import ./opts

const
  ## Floor capacity for blob output buffers (Init / Rekey).
  BlobCap = 64 * 1024

type
  PipeHandle = object
    ## Owns the raw ``ITB_Triple_*`` handle; the ``=destroy`` hook
    ## releases it (libitb closes and zeroes key material first).
    h: csize_t

  Pipeline* = ref object
    ## A Triple Pipeline session plus its exported blob bytes.
    ##
    ## The blob carries the session bundle the receiver feeds to
    ## ``openPipeline``; ``rekey`` refreshes it.
    ##
    ## Streaming-decrypt caveat: chunked Streaming AEAD verifies per
    ## chunk, so plaintext of verified chunks is released before a
    ## later chunk can fail authentication.
    raw: PipeHandle
    blobBytes: seq[byte]

proc `=copy`(dest: var PipeHandle, src: PipeHandle) {.error.}

proc `=destroy`(x: PipeHandle) =
  if x.h != 0:
    # Free runs Close first Go-side (zeroing key material); the
    # status is deliberately ignored on the release path.
    discard ITB_Triple_Free(x.h)

func outCap*(payload: int): int =
  ## Pre-allocation formula for Message / one-shot stream outputs:
  ## ``max(131072, payload * 5/4 + 131072)``.
  max(payload + payload div 4 + 131_072, 131_072)

proc retryOnce*(cap0: int,
                call: proc (buf: pointer, cap: csize_t,
                            n: ptr csize_t): cint): seq[byte] =
  ## Single retry-once dispatch site for every variable-size output
  ## buffer: pre-allocate ``cap0``, and on ``stBufferTooSmall`` retry
  ## once with the exact size the FFI reported through the length
  ## out-param. The retry is gated on the reported length strictly
  ## exceeding the current capacity.
  var buf = newSeq[byte](max(cap0, 1))
  var n: csize_t = 0
  var rc = call(addr buf[0], csize_t(buf.len), addr n)
  if int(rc) == ord(stBufferTooSmall) and int(n) > buf.len:
    buf = newSeq[byte](int(n))
    rc = call(addr buf[0], csize_t(buf.len), addr n)
  check(rc)
  buf.setLen(int(n))
  buf

func rawHandle*(p: Pipeline): csize_t =
  ## The raw libitb handle. Internal plumbing for the stream module —
  ## not part of the stable public surface.
  p.raw.h

proc initPipeline*(profile: string, opts = Opts()): Pipeline =
  ## Constructs a fresh Pipeline against the named profile. On a
  ## blob-buffer retry the Init re-runs and yields a fresh session
  ## (the undersized attempt is closed by libitb before returning).
  let optsStr = opts.build
  var handle: csize_t = 0
  let blob = retryOnce(BlobCap,
    proc (buf: pointer, cap: csize_t, n: ptr csize_t): cint =
      ITB_Triple_Init(profile.cstring, optsStr.cstring, buf, cap, n,
                      addr handle))
  Pipeline(raw: PipeHandle(h: handle), blobBytes: blob)

proc openPipeline*(profile: string, blob: openArray[byte], opts = Opts(),
                   permMaster: openArray[byte] = [],
                   wrapMaster: openArray[byte] = []): Pipeline =
  ## Reconstructs a Pipeline from a blob produced by ``initPipeline``
  ## or ``rekey``. Leave both masters empty to use the blob-embedded
  ## masters; to override, both must be supplied non-empty (a
  ## half-supplied pair is rejected).
  if blob.len == 0:
    raise newItbError(stBadInput, ord(stBadInput), "empty session blob")
  if (permMaster.len > 0) != (wrapMaster.len > 0):
    raise newItbError(stBadInput, ord(stBadInput),
                      "master override buffers must both be non-empty")
  let optsStr = opts.build
  let mastersCount: csize_t = if permMaster.len > 0: 2 else: 0
  var handle: csize_t = 0
  check(ITB_Triple_Open(profile.cstring, toPtr(blob), csize_t(blob.len),
                        optsStr.cstring,
                        toPtr(permMaster), csize_t(permMaster.len),
                        toPtr(wrapMaster), csize_t(wrapMaster.len),
                        mastersCount, addr handle))
  Pipeline(raw: PipeHandle(h: handle), blobBytes: @blob)

func blob*(p: Pipeline): seq[byte] =
  ## The exported session bundle bytes for the receiver side.
  p.blobBytes

proc rekey*(p: Pipeline, perm, wrap: openArray[byte]) =
  ## Rotates the parallax + wrapper masters and refreshes ``blob``.
  ## Must not run concurrently with cipher calls or open stream
  ## sessions on the same Pipeline.
  let handle = p.raw.h
  # openArray params cannot be captured by a closure — pin the
  # borrowed pointers and lengths first.
  let (permPtr, permLen) = (toPtr(perm), csize_t(perm.len))
  let (wrapPtr, wrapLen) = (toPtr(wrap), csize_t(wrap.len))
  p.blobBytes = retryOnce(max(BlobCap, p.blobBytes.len),
    proc (buf: pointer, cap: csize_t, n: ptr csize_t): cint =
      ITB_Triple_Rekey(handle, permPtr, permLen,
                       wrapPtr, wrapLen, buf, cap, n))

proc close*(p: Pipeline) =
  ## Zeroes the Pipeline's key material and marks it closed.
  ## Idempotent; subsequent cipher calls raise ``ItbError`` with
  ## ``stTripleClosed``.
  check(ITB_Triple_Close(p.raw.h))

proc free*(p: Pipeline) =
  ## Releases the Pipeline handle (libitb closes and zeroes key
  ## material first). Safe to call more than once; ORC reclaims
  ## un-freed handles eventually via the destructor.
  if p == nil or p.raw.h == 0:
    return
  let h = p.raw.h
  p.raw.h = 0
  discard ITB_Triple_Free(h)

proc cipherCallInto(p: Pipeline,
                    fn: proc (handle: csize_t, src: pointer,
                              srcLen: csize_t, outBuf: pointer,
                              outCap: csize_t,
                              outLen: ptr csize_t): cint {.cdecl.},
                    src: openArray[byte], dst: var seq[byte]): int =
  ## Shared body for the buffer-in / buffer-out cipher entries,
  ## writing into a caller-owned buffer. ``dst`` is grown (never
  ## shrunk) to at least ``outCap(src.len)``, so a pooled buffer is
  ## reused allocation-free across calls once warm. Returns the
  ## number of output bytes written; ``dst[0 ..< result]`` is the
  ## output. Retry-once on ``stBufferTooSmall`` grows ``dst`` to the
  ## exact size the FFI reported.
  let handle = p.raw.h
  let srcPtr = toPtr(src)
  let srcLen = csize_t(src.len)
  let cap0 = outCap(src.len)
  if dst.len < cap0:
    dst.setLen(cap0)
  var n: csize_t = 0
  var rc = fn(handle, srcPtr, srcLen, addr dst[0], csize_t(dst.len), addr n)
  if int(rc) == ord(stBufferTooSmall) and int(n) > dst.len:
    dst.setLen(int(n))
    rc = fn(handle, srcPtr, srcLen, addr dst[0], csize_t(dst.len), addr n)
  check(rc)
  if int(n) > dst.len:
    # Out-of-bounds guard: the library must never report more bytes
    # written than the capacity it was handed.
    raise newException(ValueError,
      "libitb reported " & $int(n) & " output bytes for a " &
      $dst.len & "-byte buffer")
  int(n)

proc cipherCall(p: Pipeline, fn: proc (handle: csize_t, src: pointer,
                                       srcLen: csize_t, outBuf: pointer,
                                       outCap: csize_t,
                                       outLen: ptr csize_t): cint {.cdecl.},
                src: openArray[byte]): seq[byte] =
  ## Allocating convenience wrapper over ``cipherCallInto``.
  var buf: seq[byte]
  let n = cipherCallInto(p, fn, src, buf)
  buf.setLen(n)
  buf

proc encryptMessage*(p: Pipeline, plain: openArray[byte]): seq[byte] =
  ## Single Message encrypt: one call, one self-contained wire.
  cipherCall(p, ITB_Triple_EncryptMessage, plain)

proc encryptMessageInto*(p: Pipeline, plain: openArray[byte],
                         dst: var seq[byte]): int =
  ## ``encryptMessage`` into a caller-owned buffer: ``dst`` is grown
  ## (never shrunk) as needed and ``dst[0 ..< result]`` is the wire.
  ## Reusing one buffer across calls avoids the per-call output
  ## allocation of ``encryptMessage``.
  cipherCallInto(p, ITB_Triple_EncryptMessage, plain, dst)

proc decryptMessage*(p: Pipeline, wire: openArray[byte]): seq[byte] =
  ## Receive-side counterpart of ``encryptMessage``.
  cipherCall(p, ITB_Triple_DecryptMessage, wire)

proc decryptMessageInto*(p: Pipeline, wire: openArray[byte],
                         dst: var seq[byte]): int =
  ## Receive-side counterpart of ``encryptMessageInto``:
  ## ``dst[0 ..< result]`` is the plaintext.
  cipherCallInto(p, ITB_Triple_DecryptMessage, wire, dst)

proc encryptMessage*(p: Pipeline, plain: string): seq[byte] =
  ## ``string`` convenience overload of ``encryptMessage``.
  p.encryptMessage(plain.toOpenArrayByte(0, plain.high))

proc encryptStreamOneShot*(p: Pipeline, plain: openArray[byte]): seq[byte] =
  ## One-shot stream encrypt for callers holding the whole plaintext
  ## in memory: a single FFI call through the Pipeline's stream chain.
  ## For bounded-memory streaming use the incremental ``encryptStream``
  ## session.
  cipherCall(p, ITB_Triple_EncryptStream, plain)

proc encryptStreamOneShotInto*(p: Pipeline, plain: openArray[byte],
                               dst: var seq[byte]): int =
  ## ``encryptStreamOneShot`` into a caller-owned buffer: ``dst`` is
  ## grown (never shrunk) as needed and ``dst[0 ..< result]`` is the
  ## wire. Reusing one buffer across calls avoids the per-call output
  ## allocation of ``encryptStreamOneShot``.
  cipherCallInto(p, ITB_Triple_EncryptStream, plain, dst)

proc decryptStreamOneShot*(p: Pipeline, wire: openArray[byte]): seq[byte] =
  ## Receive-side counterpart of ``encryptStreamOneShot``.
  cipherCall(p, ITB_Triple_DecryptStream, wire)

proc decryptStreamOneShotInto*(p: Pipeline, wire: openArray[byte],
                               dst: var seq[byte]): int =
  ## Receive-side counterpart of ``encryptStreamOneShotInto``:
  ## ``dst[0 ..< result]`` is the plaintext.
  cipherCallInto(p, ITB_Triple_DecryptStream, wire, dst)

proc registerProfile*(name: string, opts: Opts) =
  ## Registers a user-defined Triple profile under ``name`` so
  ## subsequent ``initPipeline`` / ``openPipeline`` calls resolve it.
  ## The opts follow the register-profile grammar validated by Go
  ## (``mode``, ``width``, ``innerHash`` / ``innerHashes``,
  ## ``keyBits``, ``macName``, ``outerCipher``, ``parallaxPalette``,
  ## ``parallaxSegmentSize``, ``chunkSize``, ``parallaxOn``,
  ## ``wrapperOn``) — build them with ``withRaw`` plus the typed
  ## setters where key names coincide. A duplicate name fails with
  ## ``stProfileExists``.
  let optsStr = opts.build
  check(ITB_Triple_RegisterProfile(name.cstring, optsStr.cstring))
