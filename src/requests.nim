## requests — a browser-impersonating HTTP client for Nim.
##
## Public surface. The client is byte-indistinguishable from a real browser at
## the network layer (TLS JA3/JA4 + HTTP/2 Akamai fingerprint, via BoringSSL /
## curl-impersonate). What it deliberately does NOT pretend to do: execute the
## JavaScript/WASM proof-of-work challenges (Cloudflare Turnstile, DataDome,
## kasada). Those need a real browser; we DETECT them and tell you, so you hand
## off instead of burning your IP. See Response.challenge.
##
## Quick start:
##   let s = newSession("chrome131", proxy = "socks5h://user:pass@host:1080")
##   let r = s.get("https://example.com")
##   if r.challenge != chNone: echo "needs a browser: ", r.challenge
##   else: echo r.status, " ", r.body.len, " bytes"
##   s.close()

import requests/[client, profiles, fingerprint]
export client, profiles, fingerprint
