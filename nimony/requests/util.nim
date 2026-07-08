## Everyday ergonomics on top of the raw request/response surface (nimony port).
##
## None of this touches the fingerprint — it is pure convenience: auth headers,
## urlencoded form bodies, and query-string building. The wire bytes are still
## whatever the profile dictates; we only add a coherent header/body when asked.

import std/base64
import requests/client

# ── auth headers ─────────────────────────────────────────────────────────────
#
# We emit a standard `Authorization` header appended to the browser's default
# header set — no fingerprint difference (Basic is just base64("user:pass"),
# exactly what curl would put on the wire) and it composes with the rest.
#
#   discard s.get(url, @[basicAuth("alice", "secret")])
#   discard s.get(url, @[bearer(token)])

proc basicAuth*(user: string, password: string): (string, string) =
  ## An `Authorization: Basic <base64(user:password)>` header tuple.
  ("Authorization", "Basic " & encode(user & ":" & password))

proc bearer*(token: string): (string, string) =
  ## An `Authorization: Bearer <token>` header tuple.
  ("Authorization", "Bearer " & token)

# ── urlencoding / forms / query strings ─────────────────────────────────────

proc isUnreserved(c: char): bool =
  (c >= 'A' and c <= 'Z') or (c >= 'a' and c <= 'z') or
  (c >= '0' and c <= '9') or c == '-' or c == '_' or c == '.' or c == '~'

proc hexDigit(n: int): char =
  if n < 10: char(int('0') + n)
  else: char(int('A') + (n - 10))

proc encodeUrl*(s: string): string =
  ## Percent-encode `s` (RFC 3986 unreserved set kept verbatim). No `std/uri`
  ## in nimony, so this is a tiny local encoder.
  result = ""
  var i = 0
  while i < s.len:
    let c = s[i]
    if isUnreserved(c):
      result.add c
    else:
      let b = int(c) and 0xFF
      result.add '%'
      result.add hexDigit(b shr 4)
      result.add hexDigit(b and 0x0F)
    inc i

proc encodeForm*(fields: seq[(string, string)]): string =
  ## application/x-www-form-urlencoded body.
  result = ""
  var first = true
  for kv in fields:
    if not first: result.add "&"
    result.add encodeUrl(kv[0])
    result.add "="
    result.add encodeUrl(kv[1])
    first = false

proc withQuery*(url: string, params: seq[(string, string)]): string =
  ## Append `params` to `url` as a percent-encoded query string.
  if params.len == 0: return url
  var hasQ = false
  var i = 0
  while i < url.len:
    if url[i] == '?': hasQ = true
    inc i
  result = url
  result.add (if hasQ: "&" else: "?")
  result.add encodeForm(params)

proc withContentType(ct: string, headers: seq[(string, string)]): seq[(string, string)] =
  result = @[("Content-Type", ct)]
  for kv in headers: result.add kv

proc postForm*(s: Session, url: string, fields: seq[(string, string)],
               headers: seq[(string, string)] = @[]): Response =
  ## POST `fields` as a urlencoded form (sets the Content-Type for you).
  s.post(url, encodeForm(fields),
         withContentType("application/x-www-form-urlencoded", headers))

proc postJson*(s: Session, url: string, body: string,
               headers: seq[(string, string)] = @[]): Response =
  ## POST a raw JSON string (sets Content-Type: application/json).
  s.post(url, body, withContentType("application/json", headers))
