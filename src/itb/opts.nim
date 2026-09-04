## URL-query builder for the opts pass-through string.
##
## The builder performs no validation — every key and value is
## rendered into a percent-encoded query string and passed through to
## Go verbatim; libitb rejects unknown keys or bad values with a
## diagnostic surfaced via ``ItbError``. Primitive / MAC / cipher /
## palette names are opaque strings.

import std/strutils

type
  Opts* = object
    ## Builder producing the URL-query-encoded opts string consumed
    ## by ``initPipeline``. Profile registration takes a ``Profile``
    ## record instead (see ``register``). Every setter returns the
    ## updated builder for fluent chaining.
    pairs: seq[(string, string)]

func toHexStr(data: openArray[byte]): string =
  result = newStringOfCap(data.len * 2)
  for b in data:
    result.add(toHex(int(b), 2).toLowerAscii)

func withRaw*(o: Opts, key, value: string): Opts =
  ## Escape hatch appending a raw ``key=value`` pair. Covers every
  ## key the Go side accepts for Init overrides.
  result = o
  result.pairs.add((key, value))

func withPermMaster*(o: Opts, master: openArray[byte]): Opts =
  ## Hex-encodes the parallax master override (``pm``).
  o.withRaw("pm", toHexStr(master))

func withWrapMaster*(o: Opts, master: openArray[byte]): Opts =
  ## Hex-encodes the wrapper master override (``wm``).
  o.withRaw("wm", toHexStr(master))

func withParallax*(o: Opts, on: bool): Opts =
  o.withRaw("withParallax", if on: "true" else: "false")

func withWrapper*(o: Opts, on: bool): Opts =
  o.withRaw("withWrapper", if on: "true" else: "false")

func withMaxWorkers*(o: Opts, n: int): Opts =
  o.withRaw("maxWorkers", $n)

func withNonceBits*(o: Opts, n: int): Opts =
  o.withRaw("nonceBits", $n)

func withBarrierFill*(o: Opts, n: int): Opts =
  o.withRaw("barrierFill", $n)

func withChunkSize*(o: Opts, n: int): Opts =
  o.withRaw("chunkSize", $n)

func withKeyBits*(o: Opts, n: int): Opts =
  o.withRaw("keyBits", $n)

func withParallaxSegmentSize*(o: Opts, n: int): Opts =
  o.withRaw("parallaxSegmentSize", $n)

func withMacName*(o: Opts, name: string): Opts =
  o.withRaw("macName", name)

func withInnerHash*(o: Opts, name: string): Opts =
  o.withRaw("innerHash", name)

func withInnerHashes*(o: Opts, names: openArray[string]): Opts =
  ## Comma-joins an 8-slot per-call inner-hash constellation into the
  ## ``innerHashes`` opts key. Parallel to the Go-side
  ## ``Opts.MixedHashes [8]string`` per-call override; slot ordering is
  ## ``[noise, lock, data1, data2, data3, start1, start2, start3]``.
  ##
  ## Fail-fast validation surfaces at Init on the Go side; a typo'd
  ## slot or width mismatch surfaces with an error naming the
  ## offending slot. When both this and ``withInnerHash`` are set, the
  ## mixed override wins on the Go side.
  o.withRaw("innerHashes", names.join(","))

func withOuterCipher*(o: Opts, name: string): Opts =
  o.withRaw("outerCipher", name)

func withParallaxPalette*(o: Opts, names: openArray[string]): Opts =
  ## Comma-joins the palette names (``parallaxPalette``).
  o.withRaw("parallaxPalette", names.join(","))

const QuerySafe = {'A'..'Z', 'a'..'z', '0'..'9', '-', '_', '.', '~', ','}

func enc(s: string): string =
  ## The accepted values are ASCII names, decimal integers,
  ## ``true`` / ``false``, hex, and comma-separated lists, so
  ## everything outside the URL-safe subset (plus ``,``) is
  ## percent-escaped byte-wise.
  result = newStringOfCap(s.len)
  for ch in s:
    if ch in QuerySafe:
      result.add(ch)
    else:
      result.add('%')
      result.add(toHex(int(ch), 2))

func build*(o: Opts): string =
  ## Renders the accumulated pairs as a query string ("" when empty).
  var parts = newSeqOfCap[string](o.pairs.len)
  for (k, v) in o.pairs:
    parts.add(enc(k) & "=" & enc(v))
  parts.join("&")

func `$`*(o: Opts): string =
  "Opts(" & o.build & ")"
