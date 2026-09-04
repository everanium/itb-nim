## itb_eitb — command-line demonstrator for the ITB Nim binding.
##
## Subcommands:
##
##     itb_eitb version                                library + binding versions
##     itb_eitb profiles                               registered profile catalogue
##     itb_eitb encrypt <profile> <in-file> <out-file> Single Message encrypt
##     itb_eitb decrypt <profile> <blob-hex> <in-file> <out-file>
##
## `encrypt` prints the session blob to stderr as hex; feed that hex
## back to `decrypt` on the receiving side. `profiles` lists the
## registered profile catalogue one name per line; the profiles that
## carry a cipher surface are the ones `encrypt` / `decrypt` accept.

import std/[os, strformat, strutils]
import ../src/itb
import ../src/itb/stream

const Usage = """usage: eitb version
       eitb profiles
       eitb encrypt <profile> <in-file> <out-file>
       eitb decrypt <profile> <blob-hex> <in-file> <out-file>"""

proc readFileBytes(path: string): seq[byte] =
  let s = readFile(path)
  result = newSeq[byte](s.len)
  if s.len > 0:
    copyMem(addr result[0], unsafeAddr s[0], s.len)

proc writeFileBytes(path: string, data: seq[byte]) =
  var s = newString(data.len)
  if data.len > 0:
    copyMem(addr s[0], unsafeAddr data[0], data.len)
  writeFile(path, s)

proc toHexStr(data: seq[byte]): string =
  result = newStringOfCap(data.len * 2)
  for b in data:
    result.add(toHex(int(b), 2).toLowerAscii)

proc fromHexStr(s: string): seq[byte] =
  if s.len mod 2 != 0:
    raise newException(ValueError, "odd-length hex string")
  result = newSeq[byte](s.len div 2)
  for i in 0 ..< result.len:
    result[i] = byte(parseHexInt(s[2 * i .. 2 * i + 1]))

proc cmdVersion() =
  echo "libitb " & version()
  echo "itb-nim " & ItbNimVersion

proc cmdProfiles() =
  for name in profiles():
    echo name

# Profiles whose canonical name begins with "streaming-" route
# through the streaming session pair instead of the Single Message
# pair.
proc isStreamingProfile(profile: string): bool =
  profile.startsWith("streaming-")

proc ensureParentDir(path: string) =
  let dir = parentDir(path)
  if dir.len > 0:
    createDir(dir)

proc streamOneShotEncrypt(pipe: Pipeline, plain: seq[byte]): seq[byte] =
  let session = pipe.encryptStream()
  session.write(plain)
  result = session.drainAll()
  session.free()

proc streamOneShotDecrypt(pipe: Pipeline, wire: seq[byte]): seq[byte] =
  let session = pipe.decryptStream()
  session.write(wire)
  result = session.drainAll()
  session.free()

proc cmdEncrypt(profile, infile, outfile: string) =
  let plain = readFileBytes(infile)
  let pipe = initPipeline(profile)
  defer: pipe.free()
  let wire =
    if isStreamingProfile(profile): streamOneShotEncrypt(pipe, plain)
    else: pipe.encryptMessage(plain)
  ensureParentDir(outfile)
  writeFileBytes(outfile, wire)
  stderr.writeLine(toHexStr(pipe.save))
  echo &"encrypted {infile} -> {outfile} ({plain.len} -> {wire.len} bytes)"

proc cmdDecrypt(profile, blobHex, infile, outfile: string) =
  let blob = fromHexStr(blobHex)
  let wire = readFileBytes(infile)
  # The profile shape travels inside the blob; the profile argument
  # only selects the Single Message or streaming cipher pair.
  let pipe = loadPipeline(blob)
  defer: pipe.free()
  let plain =
    if isStreamingProfile(profile): streamOneShotDecrypt(pipe, wire)
    else: pipe.decryptMessage(wire)
  ensureParentDir(outfile)
  writeFileBytes(outfile, plain)
  echo &"decrypted {infile} -> {outfile} ({wire.len} -> {plain.len} bytes)"

proc main(): int =
  let argv = commandLineParams()
  let knownShape =
    (argv.len == 1 and argv[0] in ["version", "profiles"]) or
    (argv.len == 4 and argv[0] == "encrypt") or
    (argv.len == 5 and argv[0] == "decrypt")
  if not knownShape:
    stderr.writeLine(Usage)
    return 2
  try:
    # Go-runtime pacing caps applied before any cipher work.
    discard setMemoryLimit(512 * 1024 * 1024)
    discard setGcPercent(20)
    case argv[0]
    of "version": cmdVersion()
    of "profiles": cmdProfiles()
    of "encrypt": cmdEncrypt(argv[1], argv[2], argv[3])
    else: cmdDecrypt(argv[1], argv[2], argv[3], argv[4])
  except CatchableError as e:
    stderr.writeLine("eitb: " & e.msg)
    return 1
  0

when isMainModule:
  quit(main())
