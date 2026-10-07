## Size and duration parsing, the monotonic clock, and the human
## renderings of sizes, rates and durations. Every rendering here is
## part of the output contract shared with the Go harness and the other
## bindings' loop utilities, so the formats are fixed to the character,
## not to taste.

import std/[monotimes, strutils]

import ./state

proc parseSize*(s: string, outValue: var int64): bool =
  ## Parses a human byte-size string ("16MB", "1MiB", "512K",
  ## "1073741824") into a byte count. Every suffix is a binary
  ## multiple: K/KB/KiB = 1024, M/MB/MiB = 1024^2, G/GB/GiB = 1024^3, B
  ## or none = bytes; matching is case-insensitive and surrounding
  ## whitespace is trimmed. Returns false on a malformed or negative
  ## value.
  const table = [
    ("KIB", 1024'i64), ("KB", 1024'i64), ("K", 1024'i64),
    ("MIB", 1048576'i64), ("MB", 1048576'i64), ("M", 1048576'i64),
    ("GIB", 1073741824'i64), ("GB", 1073741824'i64), ("G", 1073741824'i64),
    ("B", 1'i64),
  ]
  let upper = s.strip().toUpperAscii()
  if upper.len == 0 or upper.len >= 64:
    return false
  var mult = 1'i64
  var digits = upper.len
  for (suffix, m) in table:
    if upper.len >= suffix.len and upper[upper.len - suffix.len .. ^1] == suffix:
      mult = m
      digits = upper.len - suffix.len
      break
  while digits > 0 and upper[digits - 1] in Whitespace:
    dec digits
  if digits == 0:
    return false
  for c in upper[0 ..< digits]:
    if c notin {'0' .. '9'}:
      return false
  var n: int64
  try:
    n = parseBiggestInt(upper[0 ..< digits])
  except ValueError:
    return false
  if n < 0 or (mult > 1 and n > high(int64) div mult):
    return false
  outValue = n * mult
  true

proc parseDuration*(s: string, outNs: var int64): bool =
  ## Parses the Go duration grammar — a sequence of decimal numbers
  ## each followed by a unit (h, m, s, ms, us, ns), such as "30s",
  ## "5m", "1h30m", "1.5s" — into nanoseconds. Returns false on a
  ## malformed string.
  const units = [
    ("ns", 1.0), ("us", 1e3), ("ms", 1e6),
    ("s", 1e9), ("m", 60e9), ("h", 3600e9),
  ]
  if s.len == 0:
    return false
  var total = 0.0
  var i = 0
  while i < s.len:
    if s[i] notin {'0' .. '9', '.'}:
      return false
    var j = i
    while j < s.len and s[j] in {'0' .. '9', '.'}:
      inc j
    var v: float
    try:
      v = parseFloat(s[i ..< j])
    except ValueError:
      return false
    if v < 0.0:
      return false
    i = j
    var mult = 0.0
    for (unit, m) in units:
      if s.len - i >= unit.len and s[i ..< i + unit.len] == unit and
         (s.len - i == unit.len or s[i + unit.len] notin
            {'a' .. 'z', 'A' .. 'Z'}):
        mult = m
        i += unit.len
        break
    if mult == 0.0:
      return false
    total += v * mult
  if total > 9.2e18:
    return false
  outNs = int64(total)
  true

proc nowNs*(): int64 =
  ## Monotonic wall clock in nanoseconds.
  getMonoTime().ticks

proc humanBytes*(n: int64): string =
  ## Renders a byte count with a binary-unit suffix: "1.0GiB",
  ## "16.0MiB", "4.0KiB", "512B".
  if n >= 1'i64 shl 30:
    fmtF(float(n) / float(1'i64 shl 30), 1) & "GiB"
  elif n >= 1'i64 shl 20:
    fmtF(float(n) / float(1'i64 shl 20), 1) & "MiB"
  elif n >= 1'i64 shl 10:
    fmtF(float(n) / float(1'i64 shl 10), 1) & "KiB"
  else:
    $n & "B"

proc humanBytesSigned*(n: int64): string =
  ## Renders a possibly-negative byte delta with an explicit sign.
  if n < 0: "-" & humanBytes(-n) else: "+" & humanBytes(n)

proc mbPerSec*(bytes, ns: int64): float =
  ## Binary MiB per second over a nanosecond window; 0 when the window
  ## is unmeasured.
  if ns <= 0: 0.0
  else: float(bytes) / float(1 shl 20) / (float(ns) / 1e9)

proc humanRate*(bytes, ns: int64): string =
  ## Renders a throughput as "123.4MB/s" (binary MiB per second) or
  ## "n/a" for an unmeasured window.
  if ns <= 0: "n/a"
  else: fmtF(mbPerSec(bytes, ns), 1) & "MB/s"

proc fraction(fracNs: int64): string =
  ## Appends the fractional part of a nanosecond remainder (0 .. 1e9)
  ## as ".ddd" with trailing zeros removed; appends nothing for zero.
  if fracNs == 0:
    return ""
  var digits = align($fracNs, 9, '0')
  while digits.len > 0 and digits[^1] == '0':
    digits.setLen(digits.len - 1)
  "." & digits

proc humanDuration*(nsIn: int64): string =
  ## Renders a duration the way Go's time.Duration prints: below one
  ## second as milliseconds ("900ms", "1.5ms"); otherwise "[Hh][Mm]Ss"
  ## where the hour part appears when non-zero, the minute part when
  ## the hour part appears or the minutes are non-zero, and the seconds
  ## carry their fraction with trailing zeros removed ("5s", "5.003s",
  ## "1m0s", "1m5.25s", "1h0m0s"). The caller rounds first.
  var ns = nsIn
  if ns < 0:
    ns = -ns
  if ns == 0:
    return "0s"
  if ns < 1_000_000_000'i64:
    return $(ns div 1_000_000'i64) & fraction((ns mod 1_000_000'i64) * 1000'i64) & "ms"
  let hours = ns div 3_600_000_000_000'i64
  var rem = ns mod 3_600_000_000_000'i64
  let minutes = rem div 60_000_000_000'i64
  rem = rem mod 60_000_000_000'i64
  let seconds = rem div 1_000_000_000'i64
  let frac = rem mod 1_000_000_000'i64
  if hours > 0:
    result.add($hours & "h")
  if hours > 0 or minutes > 0:
    result.add($minutes & "m")
  result.add($seconds & fraction(frac) & "s")
