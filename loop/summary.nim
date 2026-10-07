## The final summary in both renderings, and the two measurements it
## folds in that are not per-worker counters: the process resident set
## and the shared library's pool counters.

import std/[atomics, strutils]

import ../src/itb3

import ./payload
import ./size
import ./state
import ./worker

proc readRss*(current: var uint64, peak: var uint64) =
  ## The process's current resident set and its high-water mark in
  ## bytes, from /proc/self/status (VmRSS and VmHWM, reported in kB).
  ## Both are zero on a platform without that file; the figures are
  ## informational and never enter the verdict.
  current = 0
  peak = 0
  var text: string
  try:
    text = readFile("/proc/self/status")
  except CatchableError:
    return
  for line in text.splitLines():
    if not (line.startsWith("VmRSS:") or line.startsWith("VmHWM:")):
      continue
    let rest = line[6 .. ^1].strip()
    var j = 0
    while j < rest.len and rest[j] in {'0' .. '9'}:
      inc j
    if j == 0:
      continue
    let kb = uint64(parseBiggestInt(rest[0 ..< j])) * 1024'u64
    if line.startsWith("VmRSS:"):
      current = kb
    else:
      peak = kb

proc poolSnapshotAlloc*(dst: var seq[int64]): bool =
  ## Pool counters. The shared library keeps process-wide monotonic
  ## totals at every pool checkout of its cipher core: per hash-array
  ## tier the starter width, checkouts, constructor misses, regrow
  ## replacements and bytes allocated; for the scratch byte pool and
  ## the parallax chunk pool the checkouts, constructor misses, regrows
  ## and regrow bytes. Two snapshots bracketing the main loop are
  ## differenced into per-run hit / miss figures that tell whether a
  ## pool keeps its items warm between calls or evicts them across GC
  ## cycles. The slot layout is read from the library: slot 0 carries
  ## the tier count T, tier i occupies the five slots at 1 + 5*i, and
  ## the two byte pools occupy the eight slots at 1 + 5*T; the buffer
  ## is sized from the binding's length query, never from a constant.
  let slots = poolStatsLen()
  if slots == 0:
    return false
  dst = newSeq[int64](slots)
  true

proc poolSnapshotTake*(dst: var seq[int64]): bool =
  try:
    discard poolStats(dst)
  except ItbError:
    return false
  true

type PoolDelta = object
  ## The differenced pool figures of one run.
  tiers: int
  starter: seq[int64]
  get: seq[int64]
  fresh: seq[int64]
  regrow: seq[int64]
  newBytes: seq[int64]
  bufGet, bufNew, bufRegrow, bufRegrowBytes: int64
  chunkGet, chunkNew, chunkRegrow, chunkRegrowBytes: int64

proc poolDiff(r: ptr RunState): PoolDelta =
  if r.poolWarmup.len < 9 or r.poolSteady.len != r.poolWarmup.len:
    return
  let w = r.poolWarmup
  let s = r.poolSteady
  let tiers = int(s[0])
  if tiers < 0 or tiers > 64 or 1 + 5 * tiers + 8 > s.len:
    return
  result.tiers = tiers
  result.starter = newSeq[int64](tiers)
  result.get = newSeq[int64](tiers)
  result.fresh = newSeq[int64](tiers)
  result.regrow = newSeq[int64](tiers)
  result.newBytes = newSeq[int64](tiers)
  for i in 0 ..< tiers:
    let base = 1 + 5 * i
    result.starter[i] = s[base + 0]
    result.get[i] = s[base + 1] - w[base + 1]
    result.fresh[i] = s[base + 2] - w[base + 2]
    result.regrow[i] = s[base + 3] - w[base + 3]
    result.newBytes[i] = s[base + 4] - w[base + 4]
  let tail = 1 + 5 * tiers
  result.bufGet = s[tail + 0] - w[tail + 0]
  result.bufNew = s[tail + 1] - w[tail + 1]
  result.bufRegrow = s[tail + 2] - w[tail + 2]
  result.bufRegrowBytes = s[tail + 3] - w[tail + 3]
  result.chunkGet = s[tail + 4] - w[tail + 4]
  result.chunkNew = s[tail + 5] - w[tail + 5]
  result.chunkRegrow = s[tail + 6] - w[tail + 6]
  result.chunkRegrowBytes = s[tail + 7] - w[tail + 7]

proc missPercent(miss, get: int64): float =
  ## Misses over checkouts as a percentage; zero when nothing was
  ## checked out.
  if get <= 0: 0.0
  else: 100.0 * float(miss) / float(get)

proc jsonString(s: string): string =
  ## Writes `s` as a JSON string literal with the escapes JSON
  ## requires.
  result = "\""
  for ch in s:
    case ch
    of '"': result.add("\\\"")
    of '\\': result.add("\\\\")
    of '\n': result.add("\\n")
    of '\r': result.add("\\r")
    of '\t': result.add("\\t")
    else:
      if ch < ' ':
        result.add("\\u" & toHex(ord(ch), 4).toLowerAscii())
      else:
        result.add(ch)
  result.add("\"")

proc effectiveGogc(flag: int): int =
  ## The effective GC percentage as the runtime reports it: the query
  ## form of the setter (a set-and-restore round trip inside the
  ## library) so the field is the same whether the value came from the
  ## flag, the environment, or the runtime default.
  if flag > 0: flag else: setGcPercent(-1)

proc finalSummary*(r: ptr RunState, elapsedNs: int64): int =
  ## Output contract. Both renderings are shared with the Go harness
  ## and every other binding's loop utility field for field: the same
  ## lines in the same order, the same keys in the same order, floats
  ## with a fixed number of decimals so the JSON is byte-identical
  ## across implementations. The Go harness alone adds its
  ## runtime-internal lines after rss: and its runtime-internal keys
  ## after parallax_chunk_pool; nothing here reproduces them because
  ## nothing they read is reachable through the C ABI.
  let cfg = addr r.cfg
  var totalIters, totalEnc, totalDec, nanosEnc, nanosDec: int64
  var errors = 0
  for i in 0 ..< cfg.workers:
    let w = addr r.workers[i]
    totalIters += w.iters
    totalEnc += w.bytesEnc
    totalDec += w.bytesDec
    nanosEnc += w.nanosEnc
    nanosDec += w.nanosDec
    if w.failed:
      inc errors

  # Throughput. Per-direction throughput divides the sum of every
  # worker's wall time in that direction by the worker count — the
  # equivalent single-stream wall time under N-way concurrency — so
  # each direction reports the aggregate rate it sustained rather than
  # collapsing to combined/2 (every iteration moves equal encrypt and
  # decrypt bytes, so a total-elapsed denominator would give both
  # directions the same figure). The combined rate keeps total elapsed
  # as the one-glance overall figure.
  let avgEnc = if nanosEnc > 0: nanosEnc div int64(cfg.workers) else: 0'i64
  let avgDec = if nanosDec > 0: nanosDec div int64(cfg.workers) else: 0'i64

  let rssDelta = int64(r.rssFinal) - int64(r.rssWarmup)
  var rssGrowth = 0.0
  if r.rssWarmup > 0:
    rssGrowth = 100.0 * float(rssDelta) / float(r.rssWarmup)

  let pd = poolDiff(r)

  let pass = errors == 0
  let rekeys = r.rekeys.load()
  let cycles = r.blobCycles.load()
  let gomaxprocs = setGomaxprocs(0)
  let streamProfile = if r.hasStream: r.streamProfile else: ""
  let msgProfile = if r.hasMsg: r.msgProfile else: ""

  if cfg.jsonOutput:
    var j = "{\"duration_seconds\":" & fmtF(float(elapsedNs) / 1e9, 3)
    j.add(",\"iterations\":" & $totalIters)
    j.add(",\"per_worker_iterations\":[")
    for i in 0 ..< cfg.workers:
      if i > 0:
        j.add(",")
      j.add($r.workers[i].iters)
    j.add("]")
    j.add(",\"bytes_encrypted\":" & $totalEnc)
    j.add(",\"bytes_decrypted\":" & $totalDec)
    j.add(",\"encrypt_mb_per_sec\":" & fmtF(mbPerSec(totalEnc, avgEnc), 1))
    j.add(",\"decrypt_mb_per_sec\":" & fmtF(mbPerSec(totalDec, avgDec), 1))
    j.add(",\"combined_mb_per_sec\":" &
          fmtF(mbPerSec(totalEnc + totalDec, elapsedNs), 1))
    j.add(",\"rekeys\":" & $rekeys)
    j.add(",\"blob_cycles\":" & $cycles)
    j.add(",\"worker_errors\":[")
    var n = 0
    for i in 0 ..< cfg.workers:
      if r.workers[i].failed:
        if n > 0:
          j.add(",")
        inc n
        j.add(jsonString(r.workers[i].error))
    j.add("]")
    j.add(",\"verdict\":\"" & (if pass: "PASS" else: "FAIL") & "\"")
    j.add(",\"shape\":\"" & shapeName(cfg.shape) & "\"")
    j.add(",\"stream_profile\":" & jsonString(streamProfile))
    j.add(",\"message_profile\":" & jsonString(msgProfile))
    j.add(",\"hash\":" & jsonString(cfg.hash))
    j.add(",\"mac\":" & jsonString(cfg.mac))
    j.add(",\"payload_bytes\":" & $cfg.payload)
    j.add(",\"payload_mode\":\"" & payloadModeName(cfg.payloadMode) & "\"")
    j.add(",\"seed\":" & $cfg.seed)
    j.add(",\"key_bits\":" & $cfg.keyBits)
    j.add(",\"nonce_bits\":" & $cfg.nonceBits)
    j.add(",\"blob_mode\":" & $cfg.blobMode)
    j.add(",\"drbg\":" & jsonString(cfg.drbg))
    j.add(",\"drbg_auto_tier\":" & jsonString(drbgAutoTier()))
    j.add(",\"chunk_size_bytes\":" & $cfg.chunkSize)
    j.add(",\"barrier_fill\":" & $cfg.barrierFill)
    j.add(",\"parallax\":\"" & onOff(cfg.parallax) & "\"")
    j.add(",\"wrapper\":\"" & onOff(cfg.wrapper) & "\"")
    j.add(",\"goroutines_requested\":" & $cfg.workersRequested)
    j.add(",\"goroutines\":" & $cfg.workers)
    j.add(",\"concurrency\":\"" & ConcurrencyMode & "\"")
    j.add(",\"gogc\":\"" & $effectiveGogc(cfg.gogc) & "\"")
    j.add(",\"memlimit_bytes\":" & $cfg.memlimit)
    j.add(",\"gomaxprocs\":" & $gomaxprocs)
    j.add(",\"microbatch_tiers\":" & jsonString(policyLabel("ITB_MICROBATCH_TIERS")))
    j.add(",\"hashpool_starters\":" & jsonString(policyLabel("ITB_HASHPOOL_STARTERS")))
    j.add(",\"rss_warmup_bytes\":" & $r.rssWarmup)
    j.add(",\"rss_peak_bytes\":" & $r.rssPeak)
    j.add(",\"rss_final_bytes\":" & $r.rssFinal)
    j.add(",\"rss_growth_percent\":" & fmtF(rssGrowth, 2))
    j.add(",\"hash_pool_tiers\":[")
    var t = 0
    for i in 0 ..< pd.tiers:
      if pd.starter[i] == 0:
        continue
      if t > 0:
        j.add(",")
      inc t
      j.add("{\"tier\":" & $i & ",\"starter\":" & $pd.starter[i] &
            ",\"get\":" & $pd.get[i] & ",\"new\":" & $pd.fresh[i] &
            ",\"regrow\":" & $pd.regrow[i] & ",\"new_bytes\":" & $pd.newBytes[i] &
            ",\"miss_percent\":" &
            fmtF(missPercent(pd.fresh[i] + pd.regrow[i], pd.get[i]), 2) & "}")
    j.add("]")
    j.add(",\"buf_pool\":{\"get\":" & $pd.bufGet & ",\"new\":" & $pd.bufNew &
          ",\"regrow\":" & $pd.bufRegrow & ",\"regrow_bytes\":" &
          $pd.bufRegrowBytes & ",\"miss_percent\":" &
          fmtF(missPercent(pd.bufRegrow, pd.bufGet), 2) & "}")
    j.add(",\"parallax_chunk_pool\":{\"get\":" & $pd.chunkGet & ",\"new\":" &
          $pd.chunkNew & ",\"regrow\":" & $pd.chunkRegrow & ",\"regrow_bytes\":" &
          $pd.chunkRegrowBytes & ",\"miss_percent\":" &
          fmtF(missPercent(pd.chunkRegrow, pd.chunkGet), 2) & "}")
    j.add("}\n")
    stdout.write(j)
    stdout.flushFile()
    return if pass: 0 else: 1

  logLine("=== FINAL ===")
  logLine("  duration: " &
          humanDuration((elapsedNs + 500_000) div 1_000_000 * 1_000_000))
  var parts = ""
  for i in 0 ..< cfg.workers:
    if i > 0:
      parts.add(" + ")
    parts.add($r.workers[i].iters)
  logLine("  iterations: " & parts & " = " & $totalIters & " total")
  logLine("  throughput: encrypt " & humanRate(totalEnc, avgEnc) &
          ", decrypt " & humanRate(totalDec, avgDec) &
          ", combined " & humanRate(totalEnc + totalDec, elapsedNs))
  logLine("  bytes: " & humanBytes(totalEnc) & " encrypted, " &
          humanBytes(totalDec) & " decrypted")
  logLine("  data integrity: " & $totalIters & "/" & $totalIters & " PASS")
  logLine("  concurrency: " & ConcurrencyMode & ", workers " & $cfg.workers &
          " (requested " & $cfg.workersRequested & ")")
  logLine("  rss: warmup " & humanBytes(int64(r.rssWarmup)) & ", peak " &
          humanBytes(int64(r.rssPeak)) & ", final " &
          humanBytes(int64(r.rssFinal)) & " (delta " &
          humanBytesSigned(rssDelta) & ", " & fmtF(rssGrowth, 1) & "% growth)")
  for i in 0 ..< pd.tiers:
    if pd.starter[i] == 0:
      continue
    logLine("  hash pool tier " & $i & " (starter " & $pd.starter[i] &
            "): get " & $pd.get[i] & ", miss " & $(pd.fresh[i] + pd.regrow[i]) &
            " (new " & $pd.fresh[i] & " + regrow " & $pd.regrow[i] & "), miss " &
            fmtF(missPercent(pd.fresh[i] + pd.regrow[i], pd.get[i]), 2) &
            "%, " & humanBytes(pd.newBytes[i]) & " allocated")
  logLine("  buf pool: get " & $pd.bufGet & ", regrow " & $pd.bufRegrow &
          " (of which fresh " & $pd.bufNew & "), miss " &
          fmtF(missPercent(pd.bufRegrow, pd.bufGet), 2) & "%, " &
          humanBytes(pd.bufRegrowBytes) & " regrown")
  logLine("  parallax chunk pool: get " & $pd.chunkGet & ", regrow " &
          $pd.chunkRegrow & " (of which fresh " & $pd.chunkNew & "), miss " &
          fmtF(missPercent(pd.chunkRegrow, pd.chunkGet), 2) & "%, " &
          humanBytes(pd.chunkRegrowBytes) & " regrown")
  if rekeys > 0:
    logLine("  rekeys: " & $rekeys)
  if cycles > 0:
    logLine("  blob cycles: " & $cycles)
  for i in 0 ..< cfg.workers:
    if r.workers[i].failed:
      logLine("  ERROR: " & r.workers[i].error)
  if pass:
    logLine("  verdict: PASS")
    return 0
  logLine("  verdict: FAIL (errors=" & $errors & ")")
  1
