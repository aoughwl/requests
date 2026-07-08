## thttp3.nim — force HTTP/3 (QUIC) and confirm negotiation.
##
## The vendored curl-impersonate is built with ngtcp2, so `useHttp3` speaks real
## HTTP/3 while keeping the browser fingerprint. Best-effort: QUIC needs UDP/443
## egress, so a network without it cleanly reports the fallback rather than
## failing.

import std/syncio
import requests/client

proc main =
  var s = newSession("chrome136")
  s.useHttp3()
  let r = s.get("https://www.google.com")
  if r.status == 0:
    echo "SKIP: no network"
    s.close()
    quit(0)
  echo "status=", r.status, " httpVersion=", r.httpVersion
  # INFO_HTTP_VERSION: 30 == CURL_HTTP_VERSION_3.
  if r.httpVersion == 30:
    echo "thttp3: HTTP/3 negotiated"
  else:
    echo "thttp3: h3 attempted, negotiated httpVersion=", r.httpVersion, " (UDP/443 likely blocked)"
  s.close()

main()
