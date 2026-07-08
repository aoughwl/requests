## Full header control — ordered overrides, default-header stripping, and a
## merge preview (nimony port).
##
## curl-impersonate lays down the browser's exact DEFAULT headers and their order
## (that ordering is part of the fingerprint). Everything here is about the
## headers *you* layer on top. Multi-value response reads (`headerAll`,
## `headerNames`, `hasHeader`) live on `Response` in client.nim.
##
## Precedence of the appended (non-default) set, lowest → highest:
##   profile.extraHeaders → session.extra → per-request headers
## unless a request sets `RequestConfig.headerOrder`, which REPLACES that whole
## computed set with a verbatim, ordered list.

import requests/client

proc orderedHeaders*(pairs: seq[(string, string)]): RequestConfig =
  ## A `RequestConfig` whose `headerOrder` is exactly `pairs`, verbatim and in
  ## order (case preserved). curl preserves the order the slist is built in, so
  ## this gives byte-exact control over what is appended to the browser defaults:
  ##   discard s.get(url, cfg = orderedHeaders(@[("X-A","1"),("X-B","2")]))
  result = RequestConfig()
  result.headerOrder = pairs

proc withoutHeaders*(names: seq[string]): RequestConfig =
  ## A `RequestConfig` that strips the named curl-default headers (curl removes a
  ## header when handed `Name:` with no value):
  ##   discard s.get(url, cfg = withoutHeaders(@["Accept-Language"]))
  result = RequestConfig()
  result.removeHeaders = names

proc mergedHeaders*(s: Session, headers: seq[(string, string)] = @[]): seq[(string, string)] =
  ## The final appended (non-default) header set a call would produce, in order
  ## and de-duplicated: profile.extraHeaders → session.extra → `headers`. This is
  ## exactly what the coherence linter sees; use it to preview/audit before send.
  mergeHeaders(s.profile.extraHeaders, s.extra, headers)
