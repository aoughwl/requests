## Spike 2: the features a real nimony port needs.
##  A) capture the response body into a Nim string via WRITEDATA (cast ptr back, append)
##  B) header slist build/free
##  C) {.strdefine.} for the lib name
##  D) a proc-type (non-closure) hook param
##  E) does nimony have try/except + defer?
import std/syncio
import std/strutils

const curlLib = "libcurl-impersonate.so"

type
  CURL = pointer
  CURLcode = cint
  CURLoption = cint
  curl_slist = object

const
  OPT_URL = CURLoption(10000 + 2)
  OPT_WRITEFUNCTION = CURLoption(20000 + 11)
  OPT_WRITEDATA = CURLoption(10000 + 1)
  OPT_HTTPHEADER = CURLoption(10000 + 23)
  OPT_SSL_VERIFYPEER = CURLoption(0 + 64)
  INFO_RESPONSE_CODE = CURLcode(0x200000 + 2)

proc curl_global_init(flags: clong): CURLcode {.cdecl, importc, dynlib: curlLib.}
proc curl_easy_init(): CURL {.cdecl, importc, dynlib: curlLib.}
proc curl_easy_cleanup(handle: CURL) {.cdecl, importc, dynlib: curlLib.}
proc curl_easy_perform(handle: CURL): CURLcode {.cdecl, importc, dynlib: curlLib.}
proc curl_easy_setopt(handle: CURL, opt: CURLoption): CURLcode {.cdecl, importc, dynlib: curlLib, varargs.}
proc curl_easy_getinfo(handle: CURL, info: CURLcode): CURLcode {.cdecl, importc, dynlib: curlLib, varargs.}
proc curl_easy_impersonate(handle: CURL, target: cstring, defaultHeaders: cint): CURLcode {.cdecl, importc, dynlib: curlLib.}
proc curl_slist_append(list: nil ptr curl_slist, s: cstring): nil ptr curl_slist {.cdecl, importc, dynlib: curlLib.}
proc curl_slist_free_all(list: nil ptr curl_slist) {.cdecl, importc, dynlib: curlLib.}

# A) body sink: WRITEDATA points at a Nim string; append bytes to it.
proc bodyCb(p: pointer, size: csize_t, nmemb: csize_t, ud: pointer): csize_t {.cdecl.} =
  let n = int(size) * int(nmemb)
  let dst = cast[ptr string](ud)
  let src = cast[ptr UncheckedArray[char]](p)
  var i = 0
  while i < n:
    dst[].add(src[i])
    inc i
  result = size * nmemb

# D) proc-type (non-closure) hook
type BeforeHook = proc(url: string): string {.nimcall.}

proc addUtm(url: string): string {.nimcall.} = url & "?utm=1"

proc get(target, url: string, hook: BeforeHook): tuple[status: int, body: string] =
  var body = ""
  let h = curl_easy_init()
  if h == nil: return (0, "")
  var t = target
  discard curl_easy_impersonate(h, toCString(t), cint(1))
  var finalUrl = hook(url)
  discard curl_easy_setopt(h, OPT_URL, toCString(finalUrl))
  discard curl_easy_setopt(h, OPT_SSL_VERIFYPEER, clong(0))
  discard curl_easy_setopt(h, OPT_WRITEFUNCTION, bodyCb)
  discard curl_easy_setopt(h, OPT_WRITEDATA, addr body)
  # B) custom header slist
  var hdrs: nil ptr curl_slist = nil
  hdrs = curl_slist_append(hdrs, cstring"X-Spike: yes")
  discard curl_easy_setopt(h, OPT_HTTPHEADER, hdrs)
  let rc = curl_easy_perform(h)
  var code: clong = 0
  discard curl_easy_getinfo(h, INFO_RESPONSE_CODE, addr code)
  curl_slist_free_all(hdrs)
  curl_easy_cleanup(h)
  discard rc
  result = (int(code), body)

proc main =
  discard curl_global_init(clong(3))
  let r = get("chrome136", "https://httpbin.org/headers", addUtm)
  echo "status=", r.status, " bodyLen=", r.body.len
  # show a slice proving the body is real JSON and our header echoed
  let hasHdr = find(r.body, "X-Spike") >= 0
  echo "X-Spike echoed=", hasHdr

main()
