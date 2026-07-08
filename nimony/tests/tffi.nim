import std/syncio
import std/strutils
import requests/ffi

proc bodyCb(p: pointer, size: csize_t, nmemb: csize_t, ud: pointer): csize_t {.cdecl.} =
  let n = int(size) * int(nmemb)
  let dst = cast[ptr string](ud)
  let src = cast[ptr UncheckedArray[char]](p)
  var i = 0
  while i < n:
    dst[].add(src[i])
    inc i
  result = size * nmemb

proc main =
  discard curl_global_init(clong(CURL_GLOBAL_ALL))
  let h = curl_easy_init()
  if h == nil:
    echo "init failed"; quit(1)
  var body = ""
  var target = "chrome136"
  discard curl_easy_impersonate(h, toCString(target), cint(1))
  var url = "https://httpbin.org/get"
  discard curl_easy_setopt(h, OPT_URL, toCString(url))
  discard curl_easy_setopt(h, OPT_WRITEFUNCTION, bodyCb)
  discard curl_easy_setopt(h, OPT_WRITEDATA, addr body)
  var hdrs: nil ptr curl_slist = nil
  hdrs = curl_slist_append(hdrs, cstring"X-Ffi: yes")
  discard curl_easy_setopt(h, OPT_HTTPHEADER, hdrs)
  let rc = curl_easy_perform(h)
  var code: clong = 0
  discard curl_easy_getinfo(h, INFO_RESPONSE_CODE, addr code)
  curl_slist_free_all(hdrs)
  curl_easy_cleanup(h)
  echo "ok=", curlOk(rc), " status=", int(code), " bodyLen=", body.len

main()
