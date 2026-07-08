## Rich response metrics, timing, and the TLS certificate chain.
##
## `readResponse` already fills `Response.info` (a `ResponseInfo` with the peer/
## local socket, sizes, redirect count, and the full curl timing breakdown).
## This module adds ergonomics on top: a human report, derived timing deltas,
## and the peer certificate chain (opt-in — it must be requested before the
## transfer with `wantCertInfo`).

import std/[strutils, strformat]
import ./ffi
import ./client

# ── derived timing ──────────────────────────────────────────────────────────

proc ttfb*(r: Response): float =
  ## Time to first byte (seconds) — `startTransfer` in the curl breakdown.
  r.info.timing.startTransfer

proc dnsTime*(r: Response): float = r.info.timing.nameLookup
proc tcpConnectTime*(r: Response): float =
  ## TCP connect duration (connect − nameLookup).
  max(0.0, r.info.timing.connect - r.info.timing.nameLookup)
proc tlsTime*(r: Response): float =
  ## TLS handshake duration (appConnect − connect); 0 for plaintext.
  if r.info.timing.appConnect <= 0: 0.0
  else: max(0.0, r.info.timing.appConnect - r.info.timing.connect)

proc report*(r: Response): string =
  ## A one-glance metrics/timing summary — useful in bot logs.
  let t = r.info.timing
  result.add &"HTTP {r.status}  {r.effectiveUrl}\n"
  result.add &"  peer     : {r.info.primaryIp}:{r.info.primaryPort}"
  if r.info.localIp.len > 0: result.add &"  (local {r.info.localIp}:{r.info.localPort})"
  result.add "\n"
  result.add &"  size     : {r.info.sizeDownload} down / {r.info.sizeUpload} up bytes"
  result.add &"  @ {r.info.speedDownload} B/s\n"
  if r.info.redirectCount > 0:
    result.add &"  redirects: {r.info.redirectCount} (next: {r.info.redirectUrl})\n"
  result.add &"  timing   : dns {t.nameLookup*1000:.1f}ms  conn {t.connect*1000:.1f}ms  " &
             &"tls {t.appConnect*1000:.1f}ms  ttfb {t.startTransfer*1000:.1f}ms  " &
             &"total {t.total*1000:.1f}ms"

# ── TLS certificate chain ───────────────────────────────────────────────────

proc wantCertInfo*(s: Session, on = true) =
  ## Ask curl to collect the peer certificate chain on the NEXT request, so
  ## `certChain` can read it afterwards. (Off by default — it costs a little.)
  ## Because each request resets the handle, prefer routing this through the
  ## per-request escape hatch for concurrency:
  ##   cfg.rawLong = @[(OPT_CERTINFO, clong(1))]
  s.setOption(OPT_CERTINFO, clong(if on: 1 else: 0))

proc certChain*(s: Session): seq[seq[(string, string)]] =
  ## The peer certificate chain from the last transfer as a list of certs, each a
  ## list of "field: value" pairs (Subject, Issuer, Start/Expire date, the PEM in
  ## a "Cert" field, …). Empty unless `wantCertInfo` was set and TLS verification
  ## ran. Leaf certificate is index 0.
  var ci: ptr CurlCertInfo
  if not curl_easy_getinfo(s.handle(), INFO_CERTINFO, addr ci).curlOk or ci.isNil:
    return
  for k in 0 ..< int(ci.numOfCerts):
    var fields: seq[(string, string)]
    var node = ci.certInfo[k]
    while node != nil:
      if not node.data.isNil:
        let line = $node.data
        let idx = line.find(':')
        if idx > 0: fields.add (line[0 ..< idx], line[idx+1 .. ^1])
      node = node.next
    result.add fields
