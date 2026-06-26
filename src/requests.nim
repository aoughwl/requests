## requests — a browser-impersonating HTTP client for Nim.
##
## Public surface. The client is byte-indistinguishable from a real browser at
## the network layer (TLS JA3/JA4 + HTTP/2 Akamai fingerprint, via BoringSSL /
## curl-impersonate).
##
## Quick start:
##   let s = newSession("chrome131", proxy = "socks5h://user:pass@host:1080")
##   let r = s.get("https://example.com")
##   echo r.status, " ", r.body.len, " bytes"
##   s.close()

import requests/[client, profiles, fingerprint, coherence]
export client, profiles, fingerprint, coherence
