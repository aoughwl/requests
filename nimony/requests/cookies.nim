## Programmatic access to the session cookie jar (nimony port).
##
## Cookies live in curl's own in-memory engine (the same one that makes
## connection reuse behave like a browser). This is a thin, typed view over it:
## read what the server set, inspect/seed/clear cookies yourself, and round-trip
## the jar to/from Netscape cookie-file text — without leaving the engine that
## keeps us coherent. Reads use INFO_COOKIELIST; writes use OPT_COOKIELIST.

import requests/ffi
import requests/client   # lowerAscii / upperAscii / trimAscii / hasPrefix / hasSuffix

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

proc splitTabs(s: string): seq[string] =
  result = @[]
  var cur = ""
  var i = 0
  while i < s.len:
    if s[i] == '\t':
      result.add cur
      cur = ""
    else:
      cur.add s[i]
    inc i
  result.add cur

proc parseI64(s: string): int64 =
  ## Non-raising decimal parse (leading '-' allowed); 0 on bad input.
  if s.len == 0: return 0
  var i = 0
  var neg = false
  if s[0] == '-':
    neg = true
    i = 1
  var v: int64 = 0
  while i < s.len:
    if s[i] < '0' or s[i] > '9': return 0
    v = v * 10 + int64(int(s[i]) - int('0'))
    inc i
  result = if neg: -v else: v

proc toBool(s: string): bool = upperAscii(s) == "TRUE"

proc parseNetscapeLine*(line: string): (Cookie, bool) =
  ## Parse one Netscape/Mozilla cookie-file line. (cookie, ok=false) for
  ## comments/blanks/malformed lines.
  var l = line
  if l.len == 0 or hasPrefix(l, "# ") or l == "#":
    return (Cookie(), false)
  var c = Cookie()
  # curl marks HttpOnly cookies with a "#HttpOnly_" prefix on the domain field.
  if hasPrefix(l, "#HttpOnly_"):
    c.httpOnly = true
    var rest = ""
    var i = "#HttpOnly_".len
    while i < l.len:
      rest.add l[i]
      inc i
    l = rest
  elif hasPrefix(l, "#"):
    return (Cookie(), false)
  let f = splitTabs(l)
  if f.len < 7: return (Cookie(), false)
  c.domain = f[0]
  c.includeSubdomains = toBool(f[1])
  c.path = f[2]
  c.secure = toBool(f[3])
  c.expires = parseI64(f[4])
  c.name = f[5]
  c.value = f[6]
  result = (c, true)

proc toNetscapeLine*(c: Cookie): string =
  ## Serialize to the one-line format curl's COOKIELIST accepts.
  let dom = (if c.httpOnly: "#HttpOnly_" else: "") & c.domain
  result = dom & "\t" &
    (if c.includeSubdomains: "TRUE" else: "FALSE") & "\t" &
    (if c.path.len > 0: c.path else: "/") & "\t" &
    (if c.secure: "TRUE" else: "FALSE") & "\t" &
    $c.expires & "\t" & c.name & "\t" & c.value

proc cookies*(s: Session): seq[Cookie] =
  ## Every cookie currently in the session jar.
  result = @[]
  var head: nil ptr CurlSlistNode = nil
  if not curlOk(curl_easy_getinfo(s.handle, INFO_COOKIELIST, addr head)):
    return
  var n = head
  while n != nil:
    let (c, ok) = parseNetscapeLine(cstrToString(n.data))
    if ok: result.add c
    n = n.next
  if head != nil:
    curl_slist_free_all(cast[nil ptr curl_slist](head))

proc cookie*(s: Session, name: string, domain = ""): string =
  ## Value of the first cookie matching `name` (and `domain`, if given); "" if absent.
  for c in s.cookies():
    if c.name == name and (domain.len == 0 or hasSuffix(c.domain, domain)):
      return c.value
  result = ""

proc hasCookie*(s: Session, name: string, domain = ""): bool =
  for c in s.cookies():
    if c.name == name and (domain.len == 0 or hasSuffix(c.domain, domain)):
      return true
  result = false

proc setCookie*(s: Session, cookie: Cookie) =
  ## Insert/replace a cookie in the jar (applied immediately).
  var line = toNetscapeLine(cookie)
  discard curl_easy_setopt(s.handle, OPT_COOKIELIST, toCString(line))

proc setCookie*(s: Session, domain: string, name: string, value: string,
                path = "/", secure = false, httpOnly = false,
                expires: int64 = 0, includeSubdomains = false) =
  ## Convenience overload to seed a single cookie by fields.
  var c = Cookie()
  c.domain = domain
  c.includeSubdomains = includeSubdomains
  c.path = path
  c.secure = secure
  c.httpOnly = httpOnly
  c.expires = expires
  c.name = name
  c.value = value
  s.setCookie(c)

proc clearCookies*(s: Session) =
  ## Erase all cookies from the jar.
  var cmd = "ALL"
  discard curl_easy_setopt(s.handle, OPT_COOKIELIST, toCString(cmd))

proc clearSessionCookies*(s: Session) =
  ## Drop only session cookies (no expiry) — like closing the browser.
  var cmd = "SESS"
  discard curl_easy_setopt(s.handle, OPT_COOKIELIST, toCString(cmd))

proc loadCookieLines*(s: Session, lines: seq[string]) =
  ## Seed the jar from Netscape cookie-file lines (e.g. read from disk).
  for line in lines:
    let stripped = trimAscii(line)
    if stripped.len > 0:
      var lv = line
      discard curl_easy_setopt(s.handle, OPT_COOKIELIST, toCString(lv))

proc dumpCookies*(s: Session): string =
  ## The jar as Netscape cookie-file text (round-trips with `loadCookieLines`).
  result = ""
  for c in s.cookies():
    result.add toNetscapeLine(c)
    result.add "\n"
