## Proxy configuration + rotation — bots rotate exits (nimony port).
##
## curl already infers the proxy scheme from the URL ("socks5h://h:1080"), so for
## a single proxy `newSession(proxy = ...)` is enough. This module adds explicit
## scheme control, a `ProxyEntry` bundling url+auth+kind, and a `ProxyPool` with a
## pick strategy so a fleet can rotate exits — per-session or per-request.
##
## nimony note: no `std/random`, so `ppRandom` uses a tiny self-contained xorshift.

import requests/client

type
  PickStrategy* = enum
    ppRoundRobin   ## deterministic cycle through the pool
    ppRandom       ## pseudo-random pick each time (local xorshift)

  ProxyEntry* = object
    url*: string      ## e.g. "http://host:8080" or "socks5h://host:1080"
    auth*: string     ## "user:password" ("" ⇒ none)
    kind*: ProxyKind  ## pkAuto ⇒ infer from the URL scheme

  ProxyPool* = ref object
    entries*: seq[ProxyEntry]
    strategy*: PickStrategy
    idx*: int
    rngState*: uint64

proc proxyEntry*(url: string, auth = "", kind = pkAuto): ProxyEntry =
  ProxyEntry(url: url, auth: auth, kind: kind)

proc newProxyPool*(entries: seq[ProxyEntry] = @[],
                   strategy = ppRoundRobin): ProxyPool =
  ## A rotating pool of proxies. Seed it now or `add` later.
  ProxyPool(entries: entries, strategy: strategy, idx: 0,
            rngState: 0x9E3779B97F4A7C15'u64)

proc add*(pool: ProxyPool, url: string, auth = "", kind = pkAuto) =
  pool.entries.add proxyEntry(url, auth, kind)

proc len*(pool: ProxyPool): int = pool.entries.len

proc nextRand(pool: ProxyPool): uint64 =
  ## xorshift64 — deterministic, no std/random dependency.
  var x = pool.rngState
  x = x xor (x shl 13)
  x = x xor (x shr 7)
  x = x xor (x shl 17)
  pool.rngState = x
  result = x

proc pick*(pool: ProxyPool): ProxyEntry =
  ## Next proxy per the pool's strategy. Returns a default (empty-url) entry if
  ## the pool is empty (no exceptions in nimony).
  if pool.entries.len == 0:
    return ProxyEntry()
  case pool.strategy
  of ppRoundRobin:
    result = pool.entries[pool.idx mod pool.entries.len]
    pool.idx = (pool.idx + 1) mod pool.entries.len
  of ppRandom:
    let r = int(nextRand(pool) mod uint64(pool.entries.len))
    result = pool.entries[r]

proc toConfig*(e: ProxyEntry): RequestConfig =
  ## A `RequestConfig` selecting this proxy — for per-request rotation:
  ##   discard s.get(url, cfg = pool.pick().toConfig())
  result = RequestConfig()
  result.proxy = e.url
  result.proxyAuth = e.auth
  result.proxyKind = e.kind

proc setProxy*(s: Session, e: ProxyEntry) =
  ## Point a session at this proxy for its subsequent requests (session-level).
  s.proxy = e.url
  s.proxyAuth = e.auth
  s.proxyKind = e.kind

proc rotate*(pool: ProxyPool, s: Session): ProxyEntry =
  ## Advance the pool and bind the chosen proxy to the session.
  result = pool.pick()
  s.setProxy(result)
