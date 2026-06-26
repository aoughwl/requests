## Everyday ergonomics on top of the raw request/response surface.
##
## None of this touches the fingerprint — it is pure convenience: typed bodies
## (JSON / form), URL query building, and response inspection. The wire bytes
## are still whatever the profile dictates; we only add a coherent Content-Type
## when you ask for a typed body (a real browser sends one too).

import std/[strutils, json, uri]
import ./client

# ── request bodies & query strings ─────────────────────────────────────────

proc withQuery*(url: string, params: openArray[(string, string)]): string =
  ## Append `params` to `url` as a percent-encoded query string.
  ##   withQuery("https://x/api", {"q": "a b", "n": "2"})
  ##   -> "https://x/api?q=a%20b&n=2"
  if params.len == 0: return url
  var parts: seq[string]
  for (k, v) in params:
    parts.add encodeUrl(k, usePlus = false) & "=" & encodeUrl(v, usePlus = false)
  let sep = if '?' in url: "&" else: "?"
  url & sep & parts.join("&")

proc encodeForm*(fields: openArray[(string, string)]): string =
  ## application/x-www-form-urlencoded body.
  var parts: seq[string]
  for (k, v) in fields:
    parts.add encodeUrl(k) & "=" & encodeUrl(v)
  parts.join("&")

proc postForm*(s: Session, url: string, fields: openArray[(string, string)],
               headers: seq[(string, string)] = @[]): Response =
  ## POST `fields` as a urlencoded form (sets Content-Type for you).
  let hdrs = @[("Content-Type", "application/x-www-form-urlencoded")] & headers
  s.post(url, encodeForm(fields), hdrs)

proc postJson*(s: Session, url: string, body: string,
               headers: seq[(string, string)] = @[]): Response =
  ## POST a raw JSON string (sets Content-Type: application/json).
  let hdrs = @[("Content-Type", "application/json")] & headers
  s.post(url, body, hdrs)

proc postJson*(s: Session, url: string, body: JsonNode,
               headers: seq[(string, string)] = @[]): Response =
  ## POST a JsonNode as application/json.
  s.postJson(url, $body, headers)

# ── response inspection ─────────────────────────────────────────────────────

proc ok*(r: Response): bool {.inline.} =
  ## True for a 2xx status with no transport error.
  r.error.len == 0 and r.status div 100 == 2

proc header*(r: Response, name: string): string =
  ## Case-insensitive lookup of a response header (first match), "" if absent.
  let want = name.toLowerAscii
  for (k, v) in r.headers:
    if k.toLowerAscii == want: return v
  ""

proc contentType*(r: Response): string =
  ## The media type sans parameters, e.g. "application/json".
  r.header("content-type").split(';')[0].strip().toLowerAscii

proc json*(r: Response): JsonNode =
  ## Parse the body as JSON (raises JsonParsingError on malformed input).
  parseJson(r.body)

proc raiseForStatus*(r: Response) =
  ## Raise IOError unless the response is 2xx (requests-style guard).
  if r.error.len > 0:
    raise newException(IOError, "request error: " & r.error)
  if r.status div 100 != 2:
    raise newException(IOError, "HTTP " & $r.status & " for " & r.effectiveUrl)
