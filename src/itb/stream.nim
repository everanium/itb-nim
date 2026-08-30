## Incremental stream sessions over an open Pipeline.
##
## A session is a dumb byte pump: ``StreamEncryptor`` takes plaintext
## in through ``write`` and yields wire through ``read`` /
## ``drainAll``; ``StreamDecryptor`` is the mirror (wire in,
## plaintext out). All chunking, MAC, envelope, and wire-format
## decisions stay inside libitb — the binding moves opaque bytes and
## relays status codes.

import ./ffi_bridge
import ./pipeline

const
  ## Feed / drain slice size used by the pump loops.
  PumpBuf* = 1 shl 20

type
  StreamHandle = object
    ## Owns the raw stream handle; the ``=destroy`` hook cancels and
    ## releases the session from any state.
    h: csize_t

  StreamSession* = ref object of RootObj
    ## Shared body for the two session directions. Holds a reference
    ## to the parent ``Pipeline`` so it cannot be collected (and its
    ## Go-side handle freed) while the session is still live.
    raw: StreamHandle
    parent: Pipeline
    ended: bool

  StreamEncryptor* = ref object of StreamSession
    ## Incremental encrypt session: plaintext in, wire out.

  StreamDecryptor* = ref object of StreamSession
    ## Incremental decrypt session: wire in, plaintext out.

proc `=copy`(dest: var StreamHandle, src: StreamHandle) {.error.}

proc `=destroy`(x: StreamHandle) =
  if x.h != 0:
    # StreamFree cancels and releases from any state, wiping the
    # Go-side spool; the status is deliberately ignored on the
    # release path.
    discard ITB_Triple_StreamFree(x.h)

proc encryptStream*(p: Pipeline): StreamEncryptor =
  ## Opens an incremental encrypt session (plaintext in, wire out).
  ## The session pins ``p`` alive for its own lifetime.
  var handle: csize_t = 0
  check(ITB_Triple_EncryptStreamBegin(p.rawHandle, addr handle))
  StreamEncryptor(raw: StreamHandle(h: handle), parent: p)

proc decryptStream*(p: Pipeline): StreamDecryptor =
  ## Opens an incremental decrypt session (wire in, plaintext out).
  ## The session pins ``p`` alive for its own lifetime.
  var handle: csize_t = 0
  check(ITB_Triple_DecryptStreamBegin(p.rawHandle, addr handle))
  StreamDecryptor(raw: StreamHandle(h: handle), parent: p)

proc write*(s: StreamSession, src: openArray[byte]) =
  ## Feeds ``src`` into the session. Blocks until the cipher chain
  ## accepts the bytes; errors are sticky.
  check(ITB_Triple_StreamWrite(s.raw.h, toPtr(src), csize_t(src.len)))

proc write*(s: StreamSession, src: string) =
  ## ``string`` convenience overload of ``write``.
  s.write(src.toOpenArrayByte(0, src.high))

proc endStream*(s: StreamSession) =
  ## Signals end-of-input. Idempotent; ``write`` after ``endStream``
  ## fails with ``stBadInput``.
  check(ITB_Triple_StreamEnd(s.raw.h))
  s.ended = true

proc readInto*(s: StreamSession,
               buf: var seq[byte]): tuple[n: int, finished: bool] =
  ## Drains up to ``buf.len`` produced bytes into the caller-owned
  ## buffer; ``buf[0 ..< result.n]`` is the drained chunk. Reusing
  ## one buffer across the drain loop avoids the per-call allocation
  ## of ``read``. ``finished`` turns true once the session has ended
  ## AND the output is fully drained. Partial drains (including empty
  ## chunks) are the normal mode. After ``endStream``, an empty-spool
  ## read blocks until the terminal bytes arrive or the session
  ## errors. ``buf`` must be non-empty.
  if buf.len == 0:
    raise newException(ValueError, "readInto requires a non-empty buffer")
  var n: csize_t = 0
  var fin: cint = 0
  check(ITB_Triple_StreamRead(s.raw.h, addr buf[0], csize_t(buf.len),
                              addr n, addr fin))
  if int(n) > buf.len:
    # Out-of-bounds guard: the library must never report more bytes
    # written than the capacity it was handed.
    raise newException(ValueError,
      "libitb reported " & $int(n) & " output bytes for a " &
      $buf.len & "-byte buffer")
  (int(n), fin != 0)

proc read*(s: StreamSession,
           maxBytes = PumpBuf): tuple[chunk: seq[byte], finished: bool] =
  ## Allocating convenience wrapper over ``readInto``: drains up to
  ## ``maxBytes`` produced bytes into a fresh chunk.
  var buf = newSeq[byte](max(maxBytes, 1))
  let (n, fin) = s.readInto(buf)
  buf.setLen(n)
  (buf, fin)

proc drainAll*(s: StreamSession): seq[byte] =
  ## Calls ``endStream`` (if not yet called) and returns every
  ## remaining output byte.
  if not s.ended:
    s.endStream()
  while true:
    let (chunk, finished) = s.read()
    result.add(chunk)
    if finished:
      return

proc pump*(s: StreamSession, source: File, sink: File) =
  ## Moves ``source`` through the session into ``sink`` with bounded
  ## memory: feed a slice, drain available output, repeat; end +
  ## final drain on source EOF.
  var piece = newSeq[byte](PumpBuf)
  while true:
    let got = source.readBytes(piece, 0, PumpBuf)
    if got == 0:
      break
    s.write(piece.toOpenArray(0, got - 1))
    # Drain whatever the chain has produced so far; a read before
    # endStream never blocks.
    while true:
      let (chunk, _) = s.read()
      if chunk.len == 0:
        break
      discard sink.writeBytes(chunk, 0, chunk.len)
  s.endStream()
  while true:
    let (chunk, finished) = s.read()
    if chunk.len > 0:
      discard sink.writeBytes(chunk, 0, chunk.len)
    if finished:
      break
  sink.flushFile()

proc free*(s: StreamSession) =
  ## Cancels (if still running) and releases the session. Safe to
  ## call from any state and more than once; ORC reclaims un-freed
  ## sessions eventually via the destructor.
  if s == nil or s.raw.h == 0:
    return
  let h = s.raw.h
  s.raw.h = 0
  discard ITB_Triple_StreamFree(h)
