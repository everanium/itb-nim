## Surface parity checks for the Nim binding; the deep suite lives in
## Go under the shipped tree.

import std/[algorithm, os, unittest]
import ../src/itb

proc payload(n: int, seed: uint64): seq[byte] =
  ## Deterministic non-trivial payload (xorshift fill).
  var x = seed or 1
  result = newSeq[byte](n)
  for i in 0 ..< n:
    x = x xor (x shl 13)
    x = x xor (x shr 7)
    x = x xor (x shl 17)
    result[i] = byte(x and 0xFF)

suite "itb nim binding":
  test "version is nonempty":
    let v = version()
    check v.len > 0
    check v[0] in {'0' .. '9'}

  test "profiles list":
    let names = profiles()
    check "singlemsg-triple-mac-v1" in names
    check "streaming-noaead-triple-v1" in names
    check names == sorted(names)
    # Every listed profile resolves and initialises on the Go side.
    for name in names:
      check lookup(name).name == name
      let pipe = initPipeline(name)
      check pipe.save.len > 0
      pipe.free()

  test "message round trip":
    let sender = initPipeline("singlemsg-triple-mac-v1")
    let receiver = loadPipeline(sender.save)
    for size in [4 * 1024, 256 * 1024]:
      let plain = payload(size, uint64(size))
      let wire = sender.encryptMessage(plain)
      check wire != plain
      let back = receiver.decryptMessage(wire)
      check back == plain
    receiver.free()
    sender.free()

  test "stream round trip":
    let sender = initPipeline("streaming-noaead-triple-v1")
    let receiver = loadPipeline(sender.save)
    let plain = payload(3 * 1024 * 1024 + 17, 42)

    let enc = sender.encryptStream()
    # Feed in uneven slices to exercise incremental writes.
    var off = 0
    for upto in [1_000_000, 2_700_001, plain.len]:
      enc.write(plain.toOpenArray(off, upto - 1))
      off = upto
    let wire = enc.drainAll()
    enc.free()
    check wire.len > 0

    let dec = receiver.decryptStream()
    dec.write(wire)
    let back = dec.drainAll()
    dec.free()
    # Boolean compare — `check back == plain` would dump multi-MiB
    # binary diffs on failure.
    check (back == plain) == true
    receiver.free()
    sender.free()

  test "stream pump round trip":
    let sender = initPipeline("streaming-aead-triple-mac-v1")
    let receiver = loadPipeline(sender.save)
    let plain = payload(2 * 1024 * 1024 + 3, 7)

    let dir = getTempDir() / "itb-nim-pump-" & $getCurrentProcessId()
    createDir(dir)
    defer: removeDir(dir)
    writeFile(dir / "plain.bin", cast[string](plain))

    var srcF = open(dir / "plain.bin", fmRead)
    var wireF = open(dir / "wire.bin", fmWrite)
    let enc = sender.encryptStream()
    enc.pump(srcF, wireF)
    enc.free()
    srcF.close()
    wireF.close()

    var wireIn = open(dir / "wire.bin", fmRead)
    var backF = open(dir / "back.bin", fmWrite)
    let dec = receiver.decryptStream()
    dec.pump(wireIn, backF)
    dec.free()
    wireIn.close()
    backF.close()

    let back = cast[seq[byte]](readFile(dir / "back.bin"))
    check (back == plain) == true
    receiver.free()
    sender.free()

  test "bad profile maps to unknown profile":
    expect ItbError:
      discard initPipeline("no-such-profile")
    try:
      discard initPipeline("no-such-profile")
    except ItbError as e:
      check e.status == stUnknownProfile
      check e.msg.len > 0
    try:
      discard lookup("no-such-profile")
      check false
    except ItbError as e:
      check e.status == stUnknownProfile

  test "negative maxWorkers opts value is clamped":
    let pipe = initPipeline("singlemsg-triple-mac-v1",
                            Opts().withMaxWorkers(-1))
    check pipe.save.len > 0
    pipe.free()

  test "tampered wire fails decrypt":
    let sender = initPipeline("singlemsg-triple-mac-v1")
    let receiver = loadPipeline(sender.save)
    var wire = sender.encryptMessage(payload(8 * 1024, 3))
    # XOR a 64-byte span so the corruption is guaranteed to hit data
    # bits (a single flipped bit can land in a noise-bit position the
    # decode path ignores).
    let mid = wire.len div 2
    for i in 0 ..< 64:
      wire[mid + i] = wire[mid + i] xor 0xFF
    try:
      discard receiver.decryptMessage(wire)
      check false
    except ItbError as e:
      check e.status == stMacFailure
    receiver.free()
    sender.free()

  test "closed pipeline reports triple closed":
    let pipe = initPipeline("singlemsg-triple-mac-v1")
    pipe.close()
    pipe.close() # idempotent
    try:
      discard pipe.encryptMessage("payload")
      check false
    except ItbError as e:
      check e.status == stTripleClosed
    pipe.free()

  test "large plaintext round trip":
    # Pattern P1: the pre-allocated output buffer plus a single retry
    # gated on strict len > cap must cover a > 1 MiB payload.
    let sender = initPipeline("singlemsg-triple-nomac-v1")
    let receiver = loadPipeline(sender.save)
    let plain = payload((1 shl 20) + 4321, 9)
    let wire = sender.encryptMessage(plain)
    let back = receiver.decryptMessage(wire)
    check (back == plain) == true
    receiver.free()
    sender.free()

  test "rekey refreshes blob":
    let sender = initPipeline("singlemsg-triple-mac-v1")
    let oldBlob = sender.save
    var perm = newSeq[byte](32)
    var wrap = newSeq[byte](32)
    for i in 0 ..< 32:
      perm[i] = 0x01
      wrap[i] = 0x02
    let rotated = sender.rekey(perm, wrap)
    check rotated != oldBlob
    check sender.save == rotated
    let receiver = loadPipeline(rotated)
    let wire = sender.encryptMessage("after rekey")
    check receiver.decryptMessage(wire) ==
        @("after rekey".toOpenArrayByte(0, 10))
    receiver.free()
    sender.free()

  test "register profile and duplicate":
    let name = "nim-binding-test-" & $getCurrentProcessId()
    # 8-entry width-256 hashes constellation, layers off.
    let prof = Profile(
      mode: "singlemsg-nomac", width: 256,
      mixedHashes: @["blake3", "blake2s", "areion256", "blake2b256",
                     "chacha20", "blake3", "blake2s", "areion256"],
      keyBits: 1024)
    register(name, prof)
    let sender = initPipeline(name)
    let receiver = loadPipeline(sender.save)
    let wire = sender.encryptMessage("custom profile")
    check receiver.decryptMessage(wire) ==
        @("custom profile".toOpenArrayByte(0, 13))
    let back = lookup(name)
    check back.name == name
    check back.mixedHashes == prof.mixedHashes
    try:
      register(name, prof)
      check false
    except ItbError as e:
      check e.status == stProfileExists
    # A non-empty name inside the record must equal the argument.
    var mismatch = lookup("singlemsg-triple-nomac-v1")
    mismatch.name = "some-other-name"
    try:
      register(name & "-mismatch", mismatch)
      check false
    except ItbError as e:
      check e.status == stBadInput
    receiver.free()
    sender.free()

  test "save then load round trip; load with masters equals rekey":
    let sender = initPipeline("singlemsg-triple-mac-v1")
    let blob = sender.save
    check sender.save == blob
    let receiver = loadPipeline(blob)
    let wire = sender.encryptMessage("in-memory")
    check receiver.decryptMessage(wire) == @("in-memory".toOpenArrayByte(0, 8))
    check receiver.save == blob
    receiver.free()
    var perm = newSeq[byte](32)
    var wrap = newSeq[byte](32)
    for i in 0 ..< 32:
      perm[i] = 0x31
      wrap[i] = 0x32
    let rotated = loadPipeline(blob, perm, wrap)
    check rotated.save != blob
    sender.rekey(perm, wrap)
    let wire2 = sender.encryptMessage("overrides")
    check rotated.decryptMessage(wire2) == @("overrides".toOpenArrayByte(0, 8))
    rotated.free()
    sender.free()

  test "inspect equals lookup; garbage is bad input":
    let sender = initPipeline("singlemsg-triple-mac-v1")
    let prof = inspect(sender.save)
    check prof.name == "singlemsg-triple-mac-v1"
    check prof.mode == "singlemsg-mac"
    check prof.width == 512
    check prof.innerHash == "areion512"
    check prof.macName == "hmac-blake3"
    check prof.wrapper and prof.parallax
    check prof == lookup("singlemsg-triple-mac-v1")
    try:
      discard inspect("not a blob".toOpenArrayByte(0, 9))
      check false
    except ItbError as e:
      check e.status == stBadInput
    sender.free()

  test "saveF then loadPipelineF round trip; missing file is bad input":
    let path = getTempDir() / ("itb-nim-persist-" & $getCurrentProcessId() & ".blob")
    let sender = initPipeline("streaming-aead-triple-mac-v1")
    sender.saveF(path)
    check readFile(path).len == sender.save.len
    check (getFilePermissions(path) * {fpGroupRead, fpGroupWrite,
           fpOthersRead, fpOthersWrite}).card == 0
    let receiver = loadPipelineF(path)
    let wire = sender.encryptStreamOneShot("on-disk".toOpenArrayByte(0, 6))
    check receiver.decryptStreamOneShot(wire) == @("on-disk".toOpenArrayByte(0, 6))
    receiver.free()
    sender.free()
    removeFile(path)
    try:
      discard loadPipelineF(path)
      check false
    except ItbError as e:
      check e.status == stBadInput

  test "maxWorkers clamps; closed pipeline reports triple closed":
    let sender = initPipeline("singlemsg-triple-mac-v1")
    sender.maxWorkers(2)
    sender.maxWorkers(-1)
    sender.maxWorkers(100_000)
    let receiver = loadPipeline(sender.save)
    receiver.maxWorkers(1)
    let wire = sender.encryptMessage("workers")
    check receiver.decryptMessage(wire) == @("workers".toOpenArrayByte(0, 6))
    receiver.close()
    try:
      discard receiver.save
      check false
    except ItbError as e:
      check e.status == stTripleClosed
    try:
      receiver.maxWorkers(2)
      check false
    except ItbError as e:
      check e.status == stTripleClosed
    receiver.free()
    sender.free()

  test "runtime knobs report previous values":
    check setMemoryLimit(-1) > 0
    check setGcPercent(-1) >= -1

  test "message into round trip with pooled buffers":
    let sender = initPipeline("singlemsg-triple-mac-v1")
    let receiver = loadPipeline(sender.save)
    var wire: seq[byte]
    var back: seq[byte]
    for size in [4 * 1024, 256 * 1024]:
      let plain = payload(size, uint64(size) + 1)
      let wn = sender.encryptMessageInto(plain, wire)
      check wn > 0 and wn <= wire.len
      let bn = receiver.decryptMessageInto(wire.toOpenArray(0, wn - 1), back)
      check bn == plain.len
      check (back[0 ..< bn] == plain) == true
    receiver.free()
    sender.free()

  test "stream readInto pooled drain round trip":
    let sender = initPipeline("streaming-noaead-triple-v1")
    let receiver = loadPipeline(sender.save)
    let plain = payload(2 * 1024 * 1024 + 5, 9)

    let enc = sender.encryptStream()
    enc.write(plain)
    enc.endStream()
    var buf = newSeq[byte](1 shl 16)
    var wire: seq[byte]
    while true:
      let (n, finished) = enc.readInto(buf)
      if n > 0:
        wire.add(buf.toOpenArray(0, n - 1))
      if finished:
        break
    enc.free()
    check wire.len > 0

    let dec = receiver.decryptStream()
    # Empty-buffer cap-guard fires before any FFI call.
    var empty: seq[byte]
    expect ValueError:
      discard dec.readInto(empty)
    dec.write(wire)
    let back = dec.drainAll()
    dec.free()
    check (back == plain) == true
    receiver.free()
    sender.free()

  test "per-call innerHashes override round trip":
    # The single-primitive width-512 base profile takes an 8-slot
    # per-call MixedHashes override (Go-side Opts.MixedHashes, wired
    # through the innerHashes= opts key). Round-trip proves the typed
    # helper's comma-join lands in the Go parser correctly.
    let mix = [
      "areion512", "blake2b512", "areion512", "blake2b512",
      "areion512", "blake2b512", "areion512", "blake2b512",
    ]
    let senderOpts = Opts().withInnerHashes(mix)
    let receiverOpts = Opts().withInnerHashes(mix)
    let sender = initPipeline("singlemsg-triple-mac-v1", senderOpts)
    let receiver = loadPipeline(sender.save)
    let plain = "per-call inner-hashes override round-trip payload"
    let wire = sender.encryptMessage(plain)
    check receiver.decryptMessage(wire) ==
        @(plain.toOpenArrayByte(0, plain.len - 1))
    receiver.free()
    sender.free()
