## Proxy configuration + rotation — bots rotate exits.
##
## curl already infers the proxy scheme from the URL ("socks5h://h:1080"), so for
## a single proxy `newSession(proxy = ...)` is enough. This module adds: explicit
## scheme control, a `ProxyEntry` bundling url+auth+kind, and a `ProxyPool` with a
## pick strategy so a fleet can rotate through many exits — per-session or
## per-request (via `RequestConfig`).

import std/random
import ./client

type
  PickStrategy* = enum
    ppRoundRobin   ## deterministic cycle through the pool
    ppRandom       ## uniform random pick each time

  ProxyEntry* = object
    url*: string      ## e.g. "http://host:8080" or "socks5h://host:1080"
    auth*: string     ## "user:password" ("" ⇒ none)
    kind*: ProxyKind  ## pkAuto ⇒ infer from the URL scheme

  ProxyPool* = ref object
    entries*: seq[ProxyEntry]
    strategy*: PickStrategy
    idx: int

proc proxyEntry*(url: string, auth = "", kind = pkAuto): ProxyEntry =
  ProxyEntry(url: url, auth: auth, kind: kind)

proc newProxyPool*(entries: openArray[ProxyEntry] = [],
                   strategy = ppRoundRobin): ProxyPool =
  ## A rotating pool of proxies. Seed it now or `add` later.
  ProxyPool(entries: @entries, strategy: strategy, idx: 0)

proc add*(pool: ProxyPool, url: string, auth = "", kind = pkAuto) =
  pool.entries.add proxyEntry(url, auth, kind)

proc len*(pool: ProxyPool): int = pool.entries.len

proc pick*(pool: ProxyPool): ProxyEntry =
  ## Next proxy per the pool's strategy. Raises if the pool is empty.
  if pool.entries.len == 0:
    raise newException(ValueError, "proxy pool is empty")
  case pool.strategy
  of ppRoundRobin:
    result = pool.entries[pool.idx mod pool.entries.len]
    pool.idx = (pool.idx + 1) mod pool.entries.len
  of ppRandom:
    result = pool.entries[rand(pool.entries.len - 1)]

# ── applying a proxy ─────────────────────────────────────────────────────────

proc toConfig*(e: ProxyEntry): RequestConfig =
  ## A `RequestConfig` selecting this proxy — for per-request rotation:
  ##   s.get(url, cfg = pool.pick().toConfig())
  RequestConfig(proxy: e.url, proxyAuth: e.auth, proxyKind: e.kind)

proc setProxy*(s: Session, e: ProxyEntry) =
  ## Point a session at this proxy for its subsequent requests (session-level).
  s.proxy = e.url
  s.proxyAuth = e.auth
  s.defaults.proxyKind = e.kind

proc rotate*(pool: ProxyPool, s: Session): ProxyEntry {.discardable.} =
  ## Advance the pool and bind the chosen proxy to the session.
  result = pool.pick()
  s.setProxy(result)
