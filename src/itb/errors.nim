## Status codes and the exception type shared by every fallible call
## in the binding.
##
## The numeric codes mirror the libitb C ABI
## (``cmd/cshared/internal/capi/errors.go``) and are stable across
## releases. Codes 11..17 are a reserved sentinel block; 19..22 belong
## to the native Blob surface (not wrapped here but relayed verbatim
## if libitb ever returns them).

type
  Status* = enum
    ## Integer status code returned by every libitb entry point.
    stOk = 0
    stBadHash = 1
    stBadKeyBits = 2
    stBadHandle = 3
    stBadInput = 4
    stBufferTooSmall = 5
    stEncryptFailed = 6
    stDecryptFailed = 7
    stSeedWidthMix = 8
    stBadMac = 9
    stMacFailure = 10
    stReserved11 = 11
    stReserved12 = 12
    stReserved13 = 13
    stReserved14 = 14
    stReserved15 = 15
    stReserved16 = 16
    stReserved17 = 17
    stBlobModeMismatch = 19
    stBlobMalformed = 20
    stBlobVersionTooNew = 21
    stBlobTooManyOpts = 22
    stStreamTruncated = 23
    stStreamAfterFinal = 24
    stTripleClosed = 25
    stProfileExists = 26
    stInternal = 99

  ItbError* = object of CatchableError
    ## Raised on every failed libitb call.
    ##
    ## ``statusCode`` carries the libitb status code when the failure
    ## came from the shared library (-1 for binding-side failures).
    ## ``lastError`` carries the ``ITB_LastError`` diagnostic captured
    ## immediately after the failing call (process-global
    ## last-write-wins — the message may belong to a different call
    ## under concurrent FFI use; the status code is always
    ## attributable).
    status*: Status
    statusCode*: int
    lastError*: string

func label*(s: Status): string =
  ## Short human-readable label for a status code.
  case s
  of stOk: "ok"
  of stBadHash: "unknown hash name"
  of stBadKeyBits: "invalid key bits"
  of stBadHandle: "invalid handle"
  of stBadInput: "invalid input"
  of stBufferTooSmall: "output buffer too small"
  of stEncryptFailed: "encrypt failed"
  of stDecryptFailed: "decrypt failed"
  of stSeedWidthMix: "seed width mismatch"
  of stBadMac: "unknown MAC name or invalid MAC handle"
  of stMacFailure: "MAC verification failed"
  of stReserved11, stReserved12, stReserved13, stReserved14,
     stReserved15, stReserved16, stReserved17: "reserved status"
  of stBlobModeMismatch: "blob mode mismatch"
  of stBlobMalformed: "malformed state blob"
  of stBlobVersionTooNew: "blob version too new"
  of stBlobTooManyOpts: "too many blob export opts"
  of stStreamTruncated: "stream truncated before terminator"
  of stStreamAfterFinal: "stream chunk after terminator"
  of stTripleClosed: "Triple Pipeline is closed"
  of stProfileExists: "profile name already registered"
  of stInternal: "internal error"

func statusFrom*(code: int): Status =
  ## Maps a raw return code onto ``Status``; unknown codes (including
  ## the enum holes) collapse to ``stInternal``.
  case code
  of 0: stOk
  of 1: stBadHash
  of 2: stBadKeyBits
  of 3: stBadHandle
  of 4: stBadInput
  of 5: stBufferTooSmall
  of 6: stEncryptFailed
  of 7: stDecryptFailed
  of 8: stSeedWidthMix
  of 9: stBadMac
  of 10: stMacFailure
  of 11: stReserved11
  of 12: stReserved12
  of 13: stReserved13
  of 14: stReserved14
  of 15: stReserved15
  of 16: stReserved16
  of 17: stReserved17
  of 19: stBlobModeMismatch
  of 20: stBlobMalformed
  of 21: stBlobVersionTooNew
  of 22: stBlobTooManyOpts
  of 23: stStreamTruncated
  of 24: stStreamAfterFinal
  of 25: stTripleClosed
  of 26: stProfileExists
  else: stInternal

proc newItbError*(status: Status, statusCode: int,
                  lastError: string): ref ItbError =
  ## Builds an ``ItbError`` with the canonical message shape.
  result = (ref ItbError)(status: status, statusCode: statusCode,
                          lastError: lastError)
  if statusCode < 0:
    result.msg = "itb: " & lastError
  elif lastError.len > 0:
    result.msg = "itb: status=" & $statusCode & " (" & status.label &
        "): " & lastError
  else:
    result.msg = "itb: status=" & $statusCode & " (" & status.label & ")"

proc raiseBindingError*(message: string) =
  ## Raises an ``ItbError`` for a binding-side failure (no libitb
  ## status code attached).
  raise newItbError(stInternal, -1, message)
