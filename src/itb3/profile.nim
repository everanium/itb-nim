## The profile record — the JSON object libitb3 accepts in ``register``,
## returns from ``lookup`` and ``inspect``, and embeds in every blob.
##
## The record is a plain data carrier: no field is validated on the
## Nim side. Field rules (mode / width / hash-width agreement, MAC
## name, palette contents, ...) are enforced by libitb3 at ``register``
## and ``load``; a rejected record surfaces as ``ItbError`` carrying
## the status code plus the ``ITB_LastError`` diagnostic.

import std/[json, options]

export options

type
  Profile* = object
    ## Resolved shape of a Triple Pipeline. Serialises to the libitb3
    ## profile JSON object; optional keys are omitted when empty /
    ## zero and decode as their defaults when absent.
    ##
    ## ``nonceBits`` and ``barrierFill`` are inspection-only: they are
    ## not part of the profile recipe, stay ``none`` on a record from
    ## ``lookup`` or built by hand, and are populated only on a record
    ## from ``inspect``, where libitb3 reads them from the blob's
    ## runtime globals snapshot. libitb3 rejects a ``register`` payload
    ## that carries either key, so clear both before handing an
    ## inspected record to ``register``.
    name*: string
      ## Registry label. Empty on a record built by hand; filled by
      ## ``lookup`` / ``inspect``. When non-empty it must equal the
      ## ``name`` argument of ``register``.
    mode*: string
      ## Pipeline mode (``singlemsg-mac``, ``singlemsg-nomac``,
      ## ``streaming-aead``, ``streaming-noaead``, ``blob-only``).
    width*: int
      ## Inner hash width in bits (128 / 256 / 512).
    innerHash*: string
      ## Single inner-hash primitive name; empty on a mixed profile.
    mixedHashes*: seq[string]
      ## Eight-slot inner-hash constellation for mixed profiles; empty
      ## on a single-primitive profile.
    keyBits*: int
      ## Session key width in bits.
    nonceBits*: Option[int]
      ## On-wire nonce width in bits, read from the blob's runtime
      ## globals. Inspection-only: ``some`` on an ``inspect`` record,
      ## ``none`` on a ``lookup`` record and on one built by hand.
    barrierFill*: Option[int]
      ## DRBG barrier fill margin, read from the blob's runtime
      ## globals. Same inspection-only lifecycle as ``nonceBits``.
    macName*: string
      ## MAC name; empty for No MAC modes.
    tagStubSize*: int
      ## MAC tag stub size; 0 for the profile default.
    chunkSize*: int
      ## Streaming chunk size; 0 for the library default.
    wrapper*: bool
      ## Whether the format-deniability wrapper layer is on.
    outerCipher*: string
      ## Outer cipher name; empty when the wrapper layer is off.
    parallax*: bool
      ## Whether the parallax layer is on.
    parallaxPalette*: seq[string]
      ## Parallax palette; empty when the parallax layer is off.
    parallaxSegmentSize*: int
      ## Parallax segment size; 0 for the library default.

proc strOf(n: JsonNode, key: string): string =
  if n.hasKey(key) and n[key].kind == JString: n[key].getStr else: ""

proc intOf(n: JsonNode, key: string): int =
  if n.hasKey(key) and n[key].kind == JInt: n[key].getInt else: 0

proc boolOf(n: JsonNode, key: string): bool =
  n.hasKey(key) and n[key].kind == JBool and n[key].getBool

proc optIntOf(n: JsonNode, key: string): Option[int] =
  if n.hasKey(key) and n[key].kind == JInt: some(n[key].getInt) else: none(int)

proc listOf(n: JsonNode, key: string): seq[string] =
  if n.hasKey(key) and n[key].kind == JArray:
    for e in n[key]:
      result.add(e.getStr)

proc fromJson*(_: typedesc[Profile], json: string): Profile =
  ## Decodes a profile JSON object as returned by libitb3.
  let n = parseJson(json)
  Profile(
    name: strOf(n, "name"),
    mode: strOf(n, "mode"),
    width: intOf(n, "width"),
    innerHash: strOf(n, "hash"),
    mixedHashes: listOf(n, "hashes"),
    keyBits: intOf(n, "keybits"),
    nonceBits: optIntOf(n, "nonce_bits"),
    barrierFill: optIntOf(n, "barrier_fill"),
    macName: strOf(n, "mac"),
    tagStubSize: intOf(n, "tagstub"),
    chunkSize: intOf(n, "chunk"),
    wrapper: boolOf(n, "wrapper"),
    outerCipher: strOf(n, "outer"),
    parallax: boolOf(n, "parallax"),
    parallaxPalette: listOf(n, "palette"),
    parallaxSegmentSize: intOf(n, "segment"))

proc toJson*(p: Profile): string =
  ## Encodes the record as the profile JSON object libitb3 accepts.
  let n = newJObject()
  if p.name.len > 0: n["name"] = %p.name
  n["mode"] = %p.mode
  n["width"] = %p.width
  if p.innerHash.len > 0: n["hash"] = %p.innerHash
  if p.mixedHashes.len > 0: n["hashes"] = %p.mixedHashes
  n["keybits"] = %p.keyBits
  if p.nonceBits.isSome: n["nonce_bits"] = %p.nonceBits.get
  if p.barrierFill.isSome: n["barrier_fill"] = %p.barrierFill.get
  if p.macName.len > 0: n["mac"] = %p.macName
  if p.tagStubSize != 0: n["tagstub"] = %p.tagStubSize
  if p.chunkSize != 0: n["chunk"] = %p.chunkSize
  n["wrapper"] = %p.wrapper
  if p.outerCipher.len > 0: n["outer"] = %p.outerCipher
  n["parallax"] = %p.parallax
  if p.parallaxPalette.len > 0: n["palette"] = %p.parallaxPalette
  if p.parallaxSegmentSize != 0: n["segment"] = %p.parallaxSegmentSize
  $n
