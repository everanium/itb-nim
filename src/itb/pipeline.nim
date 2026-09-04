## Handle-lifetime wrapper around the Triple Pipeline surface.
##
## A ``Pipeline`` is a ``ref`` — un-freed handles are reclaimed by
## ORC via the embedded handle's ``=destroy`` hook; explicit ``free``
## (or ``close``) releases the Go-side state deterministically.

import std/json

import ./errors
import ./ffi_bridge
import ./opts
import ./profile

export profile

const
  ## Floor capacity for blob / JSON output buffers (Init / Rekey /
  ## Save / Inspect / Lookup / Profiles).
  BlobCap = 64 * 1024

type
  PipeHandle = object
    ## Owns the raw ``ITB_Triple_*`` handle; the ``=destroy`` hook
    ## releases it (libitb closes and zeroes key material first).
    h: csize_t

  Pipeline* = ref object
    ## A Triple Pipeline session.
    ##
    ## ``save`` exports the session bundle the receiver feeds to
    ## ``loadPipeline``; ``rekey`` refreshes it.
    ##
    ## Streaming-decrypt caveat: chunked Streaming AEAD verifies per
    ## chunk, so plaintext of verified chunks is released before a
    ## later chunk can fail authentication.
    raw: PipeHandle

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
  ## Constructs a fresh Pipeline against the named profile. The
  ## session bundle is available through ``save``. On a blob-buffer
  ## retry the Init re-runs and yields a fresh session (the undersized
  ## attempt is closed by libitb before returning).
  let optsStr = opts.build
  var handle: csize_t = 0
  discard retryOnce(BlobCap,
    proc (buf: pointer, cap: csize_t, n: ptr csize_t): cint =
      ITB_Triple_Init(profile.cstring, optsStr.cstring, buf, cap, n,
                      addr handle))
  Pipeline(raw: PipeHandle(h: handle))

func mastersCount(permLen, wrapLen: int): csize_t =
  ## The masters pair crosses as (perm, wrap, count): both absent
  ## yields 0, otherwise 2 — libitb validates the pair.
  if permLen == 0 and wrapLen == 0: 0 else: 2

proc loadPipeline*(blob: openArray[byte],
                   permMaster: openArray[byte] = [],
                   wrapMaster: openArray[byte] = []): Pipeline =
  ## Reconstructs a Pipeline from a blob produced by ``save`` or
  ## ``rekey``. Leave both masters empty to use the blob-embedded
  ## masters; supply both to override them (the pair is validated by
  ## libitb). The profile shape travels inside the blob — no profile
  ## name, no opts. A blob whose record names a primitive absent from
  ## the local build fails with ``stRecipePrimitiveUnknown``; a
  ## record failing the profile field rules with
  ## ``stBlobMalformedRecipe``.
  var handle: csize_t = 0
  check(ITB_Triple_Load(toPtr(blob), csize_t(blob.len),
                        toPtr(permMaster), csize_t(permMaster.len),
                        toPtr(wrapMaster), csize_t(wrapMaster.len),
                        mastersCount(permMaster.len, wrapMaster.len),
                        addr handle))
  Pipeline(raw: PipeHandle(h: handle))

proc loadPipelineF*(path: string,
                    permMaster: openArray[byte] = [],
                    wrapMaster: openArray[byte] = []): Pipeline =
  ## ``loadPipeline`` for a blob stored at ``path``; the file is read
  ## inside libitb (a missing or unreadable file fails with
  ## ``stBadInput`` and the diagnostic attached).
  var handle: csize_t = 0
  check(ITB_Triple_LoadF(path.cstring,
                         toPtr(permMaster), csize_t(permMaster.len),
                         toPtr(wrapMaster), csize_t(wrapMaster.len),
                         mastersCount(permMaster.len, wrapMaster.len),
                         addr handle))
  Pipeline(raw: PipeHandle(h: handle))

proc save*(p: Pipeline): seq[byte] =
  ## The current session bundle bytes for the receiver side (the Init
  ## blob, or the bytes of the latest ``rekey``). A closed Pipeline
  ## fails with ``stTripleClosed``.
  let handle = p.raw.h
  retryOnce(BlobCap,
    proc (buf: pointer, cap: csize_t, n: ptr csize_t): cint =
      ITB_Triple_Save(handle, buf, cap, n))

proc saveF*(p: Pipeline, path: string) =
  ## Writes the current blob to ``path`` inside libitb (mode 0600; the
  ## containing directory must exist).
  check(ITB_Triple_SaveF(p.raw.h, path.cstring))

proc maxWorkers*(p: Pipeline, n: int) =
  ## Sets the worker cap for every subsequent cipher call. ``n`` is
  ## clamped by libitb (``<= 0`` selects auto, ``> 256`` becomes 256);
  ## only the handle state is reported. The cap is per-machine and
  ## never travels in the blob.
  check(ITB_Triple_MaxWorkers(p.raw.h, cint(n)))

proc rekey*(p: Pipeline, perm, wrap: openArray[byte]): seq[byte] {.discardable.} =
  ## Rotates the parallax + wrapper masters and returns the fresh blob
  ## (also available through ``save``). Must not run concurrently with
  ## cipher calls or open stream sessions on the same Pipeline.
  let handle = p.raw.h
  # openArray params cannot be captured by a closure — pin the
  # borrowed pointers and lengths first.
  let (permPtr, permLen) = (toPtr(perm), csize_t(perm.len))
  let (wrapPtr, wrapLen) = (toPtr(wrap), csize_t(wrap.len))
  retryOnce(BlobCap,
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

proc jsonOf(raw: seq[byte]): string =
  result = newString(raw.len)
  if raw.len > 0:
    copyMem(addr result[0], unsafeAddr raw[0], raw.len)

proc inspect*(blob: openArray[byte]): Profile =
  ## Decodes the profile record embedded in ``blob`` without
  ## constructing a Pipeline. No registry read, no primitive probe —
  ## a primitive name the local build lacks is returned unchanged.
  let (blobPtr, blobLen) = (toPtr(blob), csize_t(blob.len))
  let raw = retryOnce(BlobCap,
    proc (buf: pointer, cap: csize_t, n: ptr csize_t): cint =
      ITB_Triple_Inspect(blobPtr, blobLen, buf, cap, n))
  Profile.fromJson(jsonOf(raw))

proc register*(name: string, profile: Profile) =
  ## Registers a user-defined Triple profile under ``name`` so
  ## subsequent ``initPipeline`` calls resolve it. The record's field
  ## rules are validated by libitb; a duplicate name fails with
  ## ``stProfileExists``. A non-empty ``profile.name`` must equal
  ## ``name``.
  let json = profile.toJson
  check(ITB_Triple_Register(name.cstring, json.cstring))

proc lookup*(name: string): Profile =
  ## Returns the profile registered under ``name`` — a shipped
  ## catalogue entry or a prior ``register`` call. An unregistered
  ## name fails with ``stUnknownProfile``.
  let raw = retryOnce(BlobCap,
    proc (buf: pointer, cap: csize_t, n: ptr csize_t): cint =
      ITB_Triple_Lookup(name.cstring, buf, cap, n))
  Profile.fromJson(jsonOf(raw))

proc profiles*(): seq[string] =
  ## Returns the sorted list of every registered profile name.
  let raw = retryOnce(BlobCap,
    proc (buf: pointer, cap: csize_t, n: ptr csize_t): cint =
      ITB_Triple_Profiles(buf, cap, n))
  for e in parseJson(jsonOf(raw)):
    result.add(e.getStr)
