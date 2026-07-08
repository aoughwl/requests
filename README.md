# requests

An HTTP client for [Nimony](https://github.com/nim-lang/nimony) that hands the
entire TLS/JA3/JA4/HTTP-2 fingerprint off to
[curl-impersonate](https://github.com/lwthiker/curl-impersonate) — so its requests
are byte-indistinguishable from a real browser at the network layer — then puts that
whole machine (headers, cookies, proxies, TLS, DNS, redirects, timing) under
programmatic control.

**📖 Full docs → [aoughwl.github.io/docs/net-stack](https://aoughwl.github.io/docs/net-stack)**

```nim
import requests

let s = newSession("chrome136", proxy = "socks5h://user:pass@host:1080")
let r = s.get("https://example.com")
echo r.status, " HTTP/", r.httpVersionStr, " ", r.body.len, "b"
s.close()
```

Ordered headers, a coherence `audit` linter, persistent H2-coalescing handles,
file-backed cookie jars, and a `Share` pool that keeps a fleet coherent.
