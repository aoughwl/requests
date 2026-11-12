## Concurrent transfers via libcurl's multi interface (nimony port).
##
## `fetchAll` runs up to `maxConcurrent` requests at once on a single thread.
## libcurl pools connections and multiplexes HTTP/2 across them — many requests
## to one host ride one connection, exactly like a real browser: fast AND
## fingerprint-coherent (no fan-out of fresh handshakes). This is genuine I/O
## concurrency without OS threads, so there is no shared-handle hazard.
##
## Results come back in input order; a failed transfer is reported via
## `Response.error` (status 0) rather than raising, so one bad URL doesn't sink
## the batch. Each transfer gets its OWN easy handle (the session's persistent
## handle is not used here).

import requests/ffi
import requests/client

type
  Request* = object
    meth*: string
    url*: string
    body*: string
    headers*: seq[(string, string)]
    cfg*: RequestConfig
    nobody*: bool

proc req*(url: string, meth = "GET", body = "",
          headers: seq[(string, string)] = @[],
          cfg = RequestConfig(), nobody = false): Request =
  Request(meth: meth, url: url, body: body, headers: headers, cfg: cfg,
          nobody: nobody)

proc fetchAll*(s: Session, reqs: seq[Request], maxConcurrent = 8): seq[Response] =
  ## Run `reqs` concurrently (window of `maxConcurrent`). Order is preserved.
  let n = reqs.len
  result = newSeq[Response](n)
  if n == 0: return

  # pre-sized, never grown ⇒ element addresses stay valid for the C callbacks.
  var sinks = newSeq[Sink](n)
  var done = newSeq[bool](n)
  # newSeq can't default-construct a non-nil `pointer`, and `nil` is not a legal
  # literal for CURL, so grow `handles` with real handles as they are created
  # (transfers are always added in ascending index order, so handles[idx] with
  # idx == handles.len is always the next `add`).
  var handles: seq[CURL] = @[]
  # slists live in one flat seq freed after the whole batch (simplest lifetime).
  var allSlists: seq[nil ptr curl_slist] = @[]
  var i = 0
  while i < n:
    sinks[i] = default(Sink)
    sinks[i].body = ""
    sinks[i].rawHeaders = ""
    done[i] = false
    inc i

  let m = curl_multi_init()
  if m == nil:
    # can't run concurrently — degrade to sequential over the session handle.
    var k = 0
    while k < n:
      result[k] = s.request(reqs[k].meth, reqs[k].url, reqs[k].body,
                            reqs[k].headers, reqs[k].nobody, reqs[k].cfg)
      inc k
    return
  discard curl_multi_setopt(m, MOPT_PIPELINING, clong(CURLPIPE_MULTIPLEX))
  discard curl_multi_setopt(m, MOPT_MAX_TOTAL_CONNECTIONS, clong(maxConcurrent))

  var nextAdd = 0
  var active = 0

  # add the transfer at index `nextAdd`
  while nextAdd < n and active < maxConcurrent:
    let idx = nextAdd
    let h = curl_easy_init()
    handles.add h
    if h != nil:
      let ls = configureHandle(s, h, reqs[idx].meth, reqs[idx].url,
                               reqs[idx].body, reqs[idx].headers,
                               addr sinks[idx], reqs[idx].nobody, reqs[idx].cfg)
      for sl in ls: allSlists.add sl
      discard curl_multi_add_handle(m, h)
      inc active
    inc nextAdd

  var running = default(cint)
  while active > 0:
    discard curl_multi_perform(m, addr running)
    var numfds = default(cint)
    discard curl_multi_poll(m, nil, cuint(0), cint(200), addr numfds)

    var pending = default(cint)
    while true:
      let msg = curl_multi_info_read(m, addr pending)
      if msg == nil: break
      if msg.msg == CURLMSG_DONE:
        let h = msg.easyHandle
        # find the index for this handle
        var idx = -1
        var j = 0
        while j < n:
          if handles[j] == h and not done[j]:
            idx = j
            break
          inc j
        if idx >= 0:
          let res = CURLcode(cint(cast[int](msg.data)))
          if curlOk(res):
            result[idx] = readResponse(h, addr sinks[idx], reqs[idx].url)
          else:
            result[idx] = Response(status: 0, effectiveUrl: reqs[idx].url,
                                   error: errStr(res))
          done[idx] = true
        discard curl_multi_remove_handle(m, h)
        curl_easy_cleanup(h)
        dec active
        # keep the window full
        if nextAdd < n:
          let ni = nextAdd
          let nh = curl_easy_init()
          handles.add nh
          if nh != nil:
            let ls = configureHandle(s, nh, reqs[ni].meth, reqs[ni].url,
                                     reqs[ni].body, reqs[ni].headers,
                                     addr sinks[ni], reqs[ni].nobody, reqs[ni].cfg)
            for sl in ls: allSlists.add sl
            discard curl_multi_add_handle(m, nh)
            inc active
          inc nextAdd

  discard curl_multi_cleanup(m)
  for sl in allSlists:
    if sl != nil: curl_slist_free_all(sl)

proc getAll*(s: Session, urls: seq[string], maxConcurrent = 8): seq[Response] =
  ## Convenience: concurrent GET of many URLs.
  var rs = newSeq[Request](urls.len)
  var i = 0
  while i < urls.len:
    rs[i] = req(urls[i])
    inc i
  s.fetchAll(rs, maxConcurrent)
