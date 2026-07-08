## A programmatic cookie-jar manager over the live session engine (nimony port).
##
## Cookies live in curl's own per-session engine (see cookies.nim). A `CookieJar`
## is a thin management layer: list/get/set/delete cookies per domain/name, and
## round-trip the whole jar to/from Netscape cookie-file TEXT.
##
## For on-DISK persistence across runs, the simplest path is the session's own
## file engine: `newSession(cookieFile = "cookies.txt")` reads it on start and
## writes it on close (OPT_COOKIEFILE/COOKIEJAR). This jar complements that with
## in-process programmatic control.
##
## nimony note: nimony's flow analysis can't nil-check a `ref` FIELD, so the bound
## session is held in a 0-or-1-element seq instead of a nilable `Session` field.

import requests/client
import requests/cookies

type
  CookieJar* = ref object
    bound*: seq[Session]     ## 0 elements ⇒ unattached; 1 ⇒ the bound session

proc newCookieJar*(): CookieJar =
  CookieJar(bound: @[])

proc attach*(s: Session, jar: CookieJar) =
  ## Bind `jar` to session `s`. Subsequent jar ops read/write this session.
  jar.bound = @[s]

proc isAttached*(jar: CookieJar): bool = jar.bound.len > 0

proc list*(jar: CookieJar, domain = ""): seq[Cookie] =
  ## Cookies in the jar, optionally filtered to a domain (suffix match).
  result = @[]
  if jar.bound.len == 0: return
  for c in jar.bound[0].cookies():
    if domain.len == 0 or hasSuffix(c.domain, domain): result.add c

proc get*(jar: CookieJar, name: string, domain = ""): Cookie =
  ## The first cookie matching `name` (and `domain`, if given); default Cookie
  ## (empty `name`) if absent.
  result = Cookie()
  for c in jar.list(domain):
    if c.name == name: return c

proc set*(jar: CookieJar, cookie: Cookie) =
  ## Insert/replace a cookie (full control over domain/path/secure/…/expiry).
  if jar.bound.len > 0: jar.bound[0].setCookie(cookie)

proc set*(jar: CookieJar, domain: string, name: string, value: string,
          path = "/", secure = false, httpOnly = false, expires: int64 = 0,
          includeSubdomains = false) =
  if jar.bound.len > 0:
    jar.bound[0].setCookie(domain, name, value, path, secure, httpOnly,
                           expires, includeSubdomains)

proc delete*(jar: CookieJar, name: string, domain = "") =
  ## Remove cookies matching `name` (and `domain`). curl's engine has no single-
  ## cookie delete, so this rebuilds the jar without the matches.
  if jar.bound.len == 0: return
  let s = jar.bound[0]
  var keep: seq[Cookie] = @[]
  for c in s.cookies():
    let hit = c.name == name and (domain.len == 0 or hasSuffix(c.domain, domain))
    if not hit: keep.add c
  s.clearCookies()
  for c in keep: s.setCookie(c)

proc dumpText*(jar: CookieJar): string =
  ## The jar as Netscape cookie-file text (round-trips with `seedText`).
  if jar.bound.len == 0: return ""
  result = jar.bound[0].dumpCookies()

proc seedText*(jar: CookieJar, text: string) =
  ## Seed the jar from Netscape cookie-file text (splitting on newlines).
  if jar.bound.len == 0: return
  var lines: seq[string] = @[]
  var cur = ""
  var i = 0
  while i <= text.len:
    let atEnd = i == text.len
    let ch = if atEnd: '\n' else: text[i]
    if ch == '\n':
      lines.add cur
      cur = ""
    elif ch != '\r':
      cur.add ch
    inc i
  jar.bound[0].loadCookieLines(lines)
