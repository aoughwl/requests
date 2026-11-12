## TLS peer certificate-chain inspection (nimony port).
##
## After a request whose handle had `OPT_CERTINFO` enabled, curl collects the
## full peer certificate chain and exposes it via `INFO_CERTINFO` as a
## `struct curl_certinfo { int num_of_certs; struct curl_slist **certinfo; }`.
## Each `certinfo[i]` is a NUL-terminated linked list of `"Key:Value"` strings
## (e.g. `Subject:CN=example.com`, `Issuer:C=US, O=...`, `Version:2`, plus the
## PEM `Cert:` blob and `Start date:`/`Expire date:` etc.).
##
## This walks that C structure into plain nimony data. Enable collection with
## `certInfoConfig()` on the request `cfg`, then read the chain off the session:
##
##   let s = newSession("chrome136")
##   let r = s.get("https://example.com", cfg = certInfoConfig())
##   for cert in s.certChain():
##     echo cert.subject(), "  <=  ", cert.issuer()
##   s.close()

import requests/ffi
import requests/client

type
  CertInfo* = object
    ## One certificate in the peer chain, as an ordered list of (key, value)
    ## fields exactly as libcurl reports them (order + duplicates preserved).
    fields*: seq[(string, string)]

proc splitKeyValue(entry: string): (string, string) =
  ## Split `"Key:Value"` on the FIRST ':' (values may contain ':').
  var i = 0
  while i < entry.len and entry[i] != ':':
    inc i
  if i >= entry.len:
    return (entry, "")
  var key = ""
  var j = 0
  while j < i:
    key.add entry[j]
    inc j
  var val = ""
  var k = i + 1
  while k < entry.len:
    val.add entry[k]
    inc k
  result = (key, val)

proc field*(c: CertInfo, key: string): string =
  ## The value of the first field whose key matches `key` (case-insensitive);
  ## "" if absent.
  let want = lowerAscii(key)
  for kv in c.fields:
    if lowerAscii(kv[0]) == want: return kv[1]
  result = ""

proc subject*(c: CertInfo): string = c.field("Subject")
proc issuer*(c: CertInfo): string = c.field("Issuer")

proc certInfoConfig*(base = RequestConfig()): RequestConfig =
  ## A request config with peer certificate-chain collection enabled. Pass it to
  ## the request (`get`/`request`/…) so `certChain(session)` can read the result.
  result = base
  result.rawLong.add (OPT_CERTINFO, clong(1))

proc certChain*(s: Session): seq[CertInfo] =
  ## The peer certificate chain captured on the session's last request (the leaf
  ## certificate first). Empty unless the request ran with `certInfoConfig()` over
  ## TLS. Reads `INFO_CERTINFO` off the session handle; walks each per-cert slist.
  result = @[]
  if s.handle == nil: return
  var ci: nil ptr CurlCertInfo = nil
  if not curlOk(curl_easy_getinfo(s.handle, INFO_CERTINFO, addr ci)):
    return
  if ci == nil: return
  let n = int(ci.numOfCerts)
  var i = 0
  while i < n:
    var cert = CertInfo(fields: @[])
    var node = ci.certInfo[i]
    while node != nil:
      let (k, v) = splitKeyValue(cstrToString(node.data))
      cert.fields.add (k, v)
      node = node.next
    result.add cert
    inc i
