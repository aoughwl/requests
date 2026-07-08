## Concurrent transfers via libcurl's multi interface.
##
## `fetchAll` runs up to `maxConcurrent` requests at once on a single thread.
## libcurl pools connections and multiplexes HTTP/2 across them — i.e. many
## requests to the same host ride one connection, exactly like a real browser.
## That is both fast and fingerprint-coherent (no fan-out of fresh handshakes).
##
## This is genuine I/O concurrency without OS threads, so there is no shared-
## handle thread-safety hazard. Results come back in input order; a failed
## transfer is reported via `Response.error` rather than raising, so one bad
## URL doesn't sink the whole batch.

import std/tables
import ./ffi
import ./client

type
  Request* = object
    meth*: string
    url*: string
    body*: string
    headers*: seq[(string, string)]
    timeoutMs*: int          ## < 0 ⇒ inherit session
    followRedirects*: int     ## < 0 ⇒ inherit; 0 = off, 1 = on
    maxRedirs*: int           ## < 0 ⇒ inherit (default 10)
    cfg*: RequestConfig       ## advanced per-request overrides (see client.nim)
    nobody*: bool             ## issue a bodyless HEAD

proc req*(url: string, meth = "GET", body = "",
          headers: seq[(string, string)] = @[],
          timeoutMs = -1, followRedirects = -1, maxRedirs = -1,
          cfg = RequestConfig(), nobody = false): Request =
  Request(meth: meth, url: url, body: body, headers: headers,
          timeoutMs: timeoutMs, followRedirects: followRedirects,
          maxRedirs: maxRedirs, cfg: cfg, nobody: nobody)

proc fetchAll*(s: Session, reqs: openArray[Request],
               maxConcurrent = 8): seq[Response] =
  ## Run `reqs` concurrently (window of `maxConcurrent`). Order is preserved.
  var items = @reqs            # openArray can't be captured by the inner proc
  let n = items.len
  result = newSeq[Response](n)
  if n == 0: return

  # resolve base URL + run before-request hooks up front (same seam as `request`).
  for i in 0 ..< n:
    var prep = PreparedRequest(meth: items[i].meth,
                               url: resolveUrl(s, items[i].url),
                               body: items[i].body, headers: items[i].headers)
    for hk in s.beforeRequest:
      if hk != nil: hk(prep)
    items[i].meth = prep.meth
    items[i].url = prep.url
    items[i].body = prep.body
    items[i].headers = prep.headers

  # pre-sized, never grown ⇒ element addresses stay valid for the C callbacks.
  var sinks = newSeq[Sink](n)
  var slists = newSeq[seq[ptr curl_slist]](n)   # each transfer's lists to free
  var idxOf = initTable[CURL, int]()

  let m = curl_multi_init()
  if m.isNil: raise newException(IOError, "curl_multi_init failed")
  # enable HTTP/2 multiplexing + cap concurrent connections to the window.
  discard curl_multi_setopt(m, MOPT_PIPELINING, clong(CURLPIPE_MULTIPLEX))
  discard curl_multi_setopt(m, MOPT_MAX_TOTAL_CONNECTIONS, clong(maxConcurrent))

  var nextAdd = 0
  var active = 0

  proc addOne() =
    let i = nextAdd
    let h = curl_easy_init()
    if h.isNil: raise newException(IOError, "curl_easy_init failed")
    slists[i] = configureHandle(s, h, items[i].meth, items[i].url,
                                items[i].body, items[i].headers, addr sinks[i],
                                items[i].timeoutMs, items[i].followRedirects,
                                items[i].maxRedirs, nil, items[i].nobody,
                                mergeConfig(s.defaults, items[i].cfg))
    idxOf[h] = i
    discard curl_multi_add_handle(m, h)
    inc nextAdd
    inc active

  while nextAdd < n and active < maxConcurrent: addOne()

  var running: cint
  while active > 0:
    discard curl_multi_perform(m, addr running)
    var numfds: cint
    discard curl_multi_poll(m, nil, 0, 200, addr numfds)

    # reap everything that finished this cycle
    var pending: cint
    while true:
      let msg = curl_multi_info_read(m, addr pending)
      if msg.isNil: break
      if msg.msg == CURLMSG_DONE:
        let h = msg.easyHandle
        let i = idxOf[h]
        # the union's CURLcode result aliases the low bits of `data`
        let res = CURLcode(cast[uint](msg.data) and 0xFFFFFFFF'u)
        if res.curlOk:
          result[i] = readResponse(h, sinks[i], items[i].url)
          for hk in s.afterResponse:
            if hk != nil: hk(result[i])
        else:
          result[i] = Response(status: 0, effectiveUrl: items[i].url,
                               error: res.errStr)
        discard curl_multi_remove_handle(m, h)
        for sl in slists[i]:
          if sl != nil: curl_slist_free_all(sl)
        curl_easy_cleanup(h)
        idxOf.del(h)
        dec active
        if nextAdd < n: addOne()   # keep the window full

  discard curl_multi_cleanup(m)

proc getAll*(s: Session, urls: openArray[string],
             maxConcurrent = 8): seq[Response] =
  ## Convenience: concurrent GET of many URLs.
  var rs = newSeq[Request](urls.len)
  for i, u in urls: rs[i] = req(u)
  s.fetchAll(rs, maxConcurrent)
