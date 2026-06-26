## Programmatic access to the session cookie jar.
##
## Cookies live in curl's own in-memory engine (the same one that makes
## connection reuse behave like a browser). This module is a thin, typed view
## over it: read what the server set, inspect/seed/clear cookies yourself, and
## hand the jar to/from disk for login persistence — without ever leaving the
## engine that keeps us coherent.
##
##   let s = newSession("chrome136")
##   discard s.get("https://example.com")
##   for c in s.cookies(): echo c.name, "=", c.value, " (", c.domain, ")"
##   echo s.cookie("session_id")            # convenience single lookup
##   s.setCookie("example.com", "ab", "1")  # seed one
##   s.clearCookies()                       # wipe the jar

import std/strutils
import ./ffi
import ./client

type
  Cookie* = object
    domain*: string            ## host the cookie is scoped to
    includeSubdomains*: bool    ## matches subdomains of `domain`
    path*: string
    secure*: bool               ## HTTPS-only
    httpOnly*: bool             ## not exposed to document.cookie
    expires*: int64             ## unix epoch seconds; 0 ⇒ session cookie
    name*: string
    value*: string

proc toBool(s: string): bool {.inline.} = s.toUpperAscii == "TRUE"

proc parseNetscapeLine(line: string): (Cookie, bool) =
  ## Parse one Netscape/Mozilla cookie-file line. Returns (cookie, ok=false)
  ## for comments/blanks/malformed lines (skip those).
  var l = line
  if l.len == 0 or l.startsWith("# ") or l == "#": return (Cookie(), false)
  var c = Cookie()
  # curl marks HttpOnly cookies with a "#HttpOnly_" prefix on the domain field.
  if l.startsWith("#HttpOnly_"):
    c.httpOnly = true
    l = l["#HttpOnly_".len .. ^1]
  elif l.startsWith("#"):
    return (Cookie(), false)
  let f = l.split('\t')
  if f.len < 7: return (Cookie(), false)
  c.domain = f[0]
  c.includeSubdomains = toBool(f[1])
  c.path = f[2]
  c.secure = toBool(f[3])
  c.expires = try: parseBiggestInt(f[4]).int64 except ValueError: 0
  c.name = f[5]
  c.value = f[6]
  (c, true)

proc toNetscapeLine(c: Cookie): string =
  ## Serialize back to the one-line format curl's COOKIELIST accepts.
  let dom = (if c.httpOnly: "#HttpOnly_" else: "") & c.domain
  @[dom,
    (if c.includeSubdomains: "TRUE" else: "FALSE"),
    (if c.path.len > 0: c.path else: "/"),
    (if c.secure: "TRUE" else: "FALSE"),
    $c.expires, c.name, c.value].join("\t")

proc cookies*(s: Session): seq[Cookie] =
  ## Every cookie currently in the session jar.
  var head: ptr CurlSlistNode
  if not curl_easy_getinfo(s.handle, INFO_COOKIELIST, addr head).curlOk:
    return
  var n = head
  while n != nil:
    if not n.data.isNil:
      let (c, ok) = parseNetscapeLine($n.data)
      if ok: result.add c
    n = n.next
  if head != nil: curl_slist_free_all(cast[ptr curl_slist](head))

proc cookie*(s: Session, name: string, domain = ""): string =
  ## Value of the first cookie matching `name` (and `domain`, if given).
  ## Empty string if absent.
  for c in s.cookies():
    if c.name == name and (domain.len == 0 or c.domain.endsWith(domain)):
      return c.value
  ""

proc hasCookie*(s: Session, name: string, domain = ""): bool =
  for c in s.cookies():
    if c.name == name and (domain.len == 0 or c.domain.endsWith(domain)):
      return true
  false

proc setCookie*(s: Session, cookie: Cookie) =
  ## Insert/replace a cookie in the jar (applied immediately).
  discard curl_easy_setopt(s.handle, OPT_COOKIELIST, toNetscapeLine(cookie).cstring)

proc setCookie*(s: Session, domain, name, value: string, path = "/",
                secure = false, httpOnly = false, expires: int64 = 0,
                includeSubdomains = false) =
  ## Convenience overload to seed a single cookie by fields.
  s.setCookie(Cookie(domain: domain, includeSubdomains: includeSubdomains,
                     path: path, secure: secure, httpOnly: httpOnly,
                     expires: expires, name: name, value: value))

proc clearCookies*(s: Session) =
  ## Erase all cookies from the jar.
  discard curl_easy_setopt(s.handle, OPT_COOKIELIST, "ALL".cstring)

proc clearSessionCookies*(s: Session) =
  ## Drop only session cookies (no expiry) — like closing the browser.
  discard curl_easy_setopt(s.handle, OPT_COOKIELIST, "SESS".cstring)

proc loadCookies*(s: Session, lines: openArray[string]) =
  ## Seed the jar from Netscape cookie-file lines (e.g. read from disk).
  for line in lines:
    let stripped = line.strip()
    if stripped.len > 0:
      discard curl_easy_setopt(s.handle, OPT_COOKIELIST, line.cstring)

proc dumpCookies*(s: Session): string =
  ## The jar as a Netscape cookie-file text (round-trips with `loadCookies`).
  for c in s.cookies():
    result.add toNetscapeLine(c)
    result.add "\n"
