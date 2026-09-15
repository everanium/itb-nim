## Thin Nim proxy over the libitb3 shared library's Triple Pipeline
## surface.
##
## The package wraps the ``ITB_Triple_*`` C ABI exported by
## ``cmd/cshared`` (libitb3.so / .dylib / .dll) through
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
##   import itb3
##
##   let sender = initPipeline("singlemsg-triple-mac-v1")
##   let receiver = loadPipeline(sender.save)
##   let wire = sender.encryptMessage("hello")
##   assert receiver.decryptMessage(wire) == @("hello".toOpenArrayByte(0, 4))

import itb3/errors
import itb3/opts
import itb3/pipeline
import itb3/stream
import itb3/runtime

export errors, opts, pipeline, stream, runtime

const ItbNimVersion* = "0.5.1"
  ## Binding version. Tracks the Nim wrapper; call ``version()`` for
  ## the underlying libitb3 library version.
