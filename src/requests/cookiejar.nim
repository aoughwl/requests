## First-class cookie jars — in-memory and file-backed (Netscape format).
##
## Cookies live in curl's own per-session engine (that is what keeps reuse
## browser-coherent — see cookies.nim). A `CookieJar` is a thin persistence +
## management layer over that engine: bind it to a session, seed the session from
## a file on disk, manage cookies per domain/name programmatically (honoring
## domain/path/secure/httponly/expiry), and persist back — with optional
## auto-save on close. Share one engine across sessions with a `Share` (share.nim);
## share one *file* across separate runs with a jar `path`.
##
##   let jar = newCookieJar("cookies.txt", autoSave = true)
##   let s = newSession("chrome136")
##   s.attach(jar)                       # seed from disk
##   discard s.get("https://site/login")
##   s.close(jar)                        # persists on the way out
##
## TODO(ephemeral): a truly per-REQUEST jar would need its own curl handle (the
## engine is per-handle). Until then, `clone` a session for an isolated jar.

import std/[os, strutils]
import ./client
import ./cookies

type
  CookieJar* = ref object
    path*: string        ## backing file ("" ⇒ memory-only, session engine only)
    autoSave*: bool      ## persist automatically on `close(session, jar)`
    session: Session     ## the bound session (nil until `attach`)

const netscapeHeader = "# Netscape HTTP Cookie File\n# Managed by requests\n\n"

proc newCookieJar*(path = "", autoSave = false): CookieJar =
  ## A cookie jar. With a `path`, it round-trips the session's cookies to a
  ## Netscape cookie file; without one it is a pure handle to the live engine.
  CookieJar(path: path, autoSave: autoSave)

proc saveTo*(jar: CookieJar, path: string) =
  ## Write the bound session's cookies to `path` as a Netscape cookie file.
  if jar.session == nil: return
  writeFile(path, netscapeHeader & dumpCookies(jar.session))

proc save*(jar: CookieJar) =
  ## Persist to the jar's own `path` (no-op if it is memory-only).
  if jar.path.len > 0: jar.saveTo(jar.path)

proc attach*(s: Session, jar: CookieJar) =
  ## Bind `jar` to session `s` and, if the jar has a file that exists, seed the
  ## session engine from it. Subsequent jar ops read/write this session.
  jar.session = s
  if jar.path.len > 0 and fileExists(jar.path):
    s.loadCookies(readFile(jar.path).splitLines())

proc close*(s: Session, jar: CookieJar) =
  ## Close the session, first persisting the jar if `autoSave` is on.
  if jar.autoSave: jar.save()
  s.close()

# ── programmatic management (delegates to the live engine) ──────────────────

proc list*(jar: CookieJar, domain = ""): seq[Cookie] =
  ## Cookies in the jar, optionally filtered to a domain (suffix match).
  if jar.session == nil: return
  for c in jar.session.cookies():
    if domain.len == 0 or c.domain.endsWith(domain): result.add c

proc get*(jar: CookieJar, name: string, domain = ""): Cookie =
  ## The first cookie matching `name` (and `domain`, if given); default Cookie
  ## with empty `name` if absent.
  for c in jar.list(domain):
    if c.name == name: return c

proc set*(jar: CookieJar, cookie: Cookie) =
  ## Insert/replace a cookie (full control over domain/path/secure/…/expiry).
  if jar.session != nil: jar.session.setCookie(cookie)

proc set*(jar: CookieJar, domain, name, value: string, path = "/",
          secure = false, httpOnly = false, expires: int64 = 0,
          includeSubdomains = false) =
  jar.set(Cookie(domain: domain, includeSubdomains: includeSubdomains, path: path,
                 secure: secure, httpOnly: httpOnly, expires: expires,
                 name: name, value: value))

proc delete*(jar: CookieJar, name: string, domain = "") =
  ## Remove cookies matching `name` (and `domain`). curl's engine has no single-
  ## cookie delete, so this rebuilds the jar without the matches.
  if jar.session == nil: return
  let keep = block:
    var acc: seq[Cookie]
    for c in jar.session.cookies():
      let hit = c.name == name and (domain.len == 0 or c.domain.endsWith(domain))
      if not hit: acc.add c
    acc
  jar.session.clearCookies()
  for c in keep: jar.session.setCookie(c)
