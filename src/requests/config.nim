## Small composable builders for `RequestConfig` — DNS, connection, and redirect
## control that doesn't warrant its own module. Combine with the header (headers.
## nim), proxy (proxy.nim) and TLS (tls.nim) builders via `merge`.

import ./ffi
import ./client

proc merge*(a, b: RequestConfig): RequestConfig =
  ## Overlay `b` onto `a` (b's set fields win). Lets you compose builders:
  ##   let cfg = orderedHeaders(hs).merge(pinToIp("1.2.3.4"))
  mergeConfig(a, b)

# ── DNS / connection ────────────────────────────────────────────────────────

proc pinHost*(host: string, port: int, address: string): RequestConfig =
  ## Pin `host:port` to a specific IP (CURLOPT_RESOLVE) — hit one edge/CDN node
  ## regardless of DNS. `address` may be a comma list of IPs.
  RequestConfig(resolve: @[host & ":" & $port & ":" & address])

proc connectVia*(host: string, port: int, connectHost: string,
                 connectPort: int): RequestConfig =
  ## Route requests for `host:port` to a different endpoint while keeping the
  ## original Host/SNI (CURLOPT_CONNECT_TO).
  RequestConfig(connectTo: @[host & ":" & $port & ":" & connectHost & ":" & $connectPort])

proc bindTo*(interfaceName = "", localPort = 0): RequestConfig =
  ## Bind the source interface/IP and/or local port for the connection.
  RequestConfig(interfaceName: interfaceName, localPort: localPort)

proc useDns*(servers: string): RequestConfig =
  ## Override the DNS servers (needs a c-ares-backed curl build).
  RequestConfig(dnsServers: servers)

proc forceIPv4*(): RequestConfig = RequestConfig(ipFamily: ipV4)
proc forceIPv6*(): RequestConfig = RequestConfig(ipFamily: ipV6)

# ── HTTP version / redirects ────────────────────────────────────────────────

proc forceHttp*(v: ForceHttpVersion): RequestConfig =
  ## Force the wire HTTP version (breaks version-coherence if it disagrees with
  ## what the real browser would negotiate — use sparingly).
  RequestConfig(httpVersion: v)

proc keepAuthAcrossHosts*(on = true): RequestConfig =
  ## Keep (or drop) the Authorization header when a redirect changes host.
  RequestConfig(unrestrictedAuth: if on: triOn else: triOff)

proc autoReferer*(on = true): RequestConfig =
  ## Have curl set Referer automatically as it follows redirects (browser-like).
  RequestConfig(autoReferer: if on: triOn else: triOff)

proc keepPostOnRedirect*(on = true): RequestConfig =
  ## Preserve the POST method+body across 301/302/303 redirects (default: curl
  ## downgrades to GET, like a browser).
  RequestConfig(postRedir: if on: REDIR_POST_ALL else: 0)
