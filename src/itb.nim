## Thin Nim proxy over the libitb shared library's Triple Pipeline
## surface.
##
## The package wraps the ``ITB_Triple_*`` C ABI exported by
## ``cmd/cshared`` (libitb.so / .dylib / .dll) through
## ``{.importc, dynlib.}`` declarations — runtime FFI, no
## compile-time link. Every hash-name / MAC-name / cipher-name /
## profile-name is an opaque string passed through to Go for
## validation; the binding carries no ITB construction logic of its
## own.
##
## Example:
##
## .. code-block:: nim
##
##   import itb
##
##   let sender = initPipeline("singlemsg-triple-mac-v1")
##   let receiver = openPipeline("singlemsg-triple-mac-v1", sender.blob)
##   let wire = sender.encryptMessage("hello")
##   assert receiver.decryptMessage(wire) == @("hello".toOpenArrayByte(0, 4))

import itb/errors
import itb/opts
import itb/pipeline
import itb/stream
import itb/runtime

export errors, opts, pipeline, stream, runtime

const ItbNimVersion* = "0.3.1"
  ## Binding version. Tracks the Nim wrapper; call ``version()`` for
  ## the underlying libitb library version.
