## Live test: file-backed cookie jar persistence across sessions.
## Session A sets a cookie server-side, saves the jar to a temp file; session B
## loads that file and confirms the cookie is echoed by httpbin.org/cookies.
import std/syncio
import requests
import requests/client   # findSub

var failed = 0
proc check(cond: bool, msg: string) =
  if cond: echo "  ok: ", msg
  else:
    echo "  FAIL: ", msg
    inc failed

const jarPath = "/tmp/nimony-requests-cookiejar.txt"

proc slurp(path: string): string =
  ## Non-raising file read (readFile is `.raises`).
  result = ""
  var f = default(File)
  if not open(f, path, fmRead): return
  var line = ""
  while readLine(f, line):
    result.add line
    result.add "\n"
  close(f)

proc main =
  # Session A: acquire a server-set cookie, then persist the jar to disk.
  block:
    let a = newSession("chrome136")
    let r = a.get("https://httpbin.org/cookies/set?flavour=chocolate")
    echo "A cookies/set -> status=", r.status
    check(r.status == 200, "A cookies/set 200 (redirect followed)")
    check(a.cookie("flavour") == "chocolate", "A engine captured the cookie")
    check(a.saveCookies(jarPath), "A saveCookies wrote the file")
    a.close()

  # The file should exist and mention the cookie.
  block:
    let text = slurp(jarPath)
    check(findSub(text, "flavour") >= 0 and findSub(text, "chocolate") >= 0,
          "jar file contains the persisted cookie")

  # Session B: load the file, confirm the cookie is present and sent on the wire.
  block:
    let b = newSession("chrome136")
    check(b.loadCookies(jarPath), "B loadCookies read the file")
    check(b.cookie("flavour") == "chocolate", "B engine has the loaded cookie")
    let r = b.get("https://httpbin.org/cookies")
    echo "B /cookies -> status=", r.status
    check(r.status == 200, "B /cookies 200")
    check(findSub(r.body, "flavour") >= 0 and findSub(r.body, "chocolate") >= 0,
          "server echoes the loaded cookie back")
    b.close()

  # Auto-persist path: cookieFile() binds a file that flushes on close.
  block:
    let c = newSession("chrome136")
    c.cookieFile("/tmp/nimony-requests-autojar.txt")
    check(c.loadCookies(jarPath), "C seeds from the earlier jar")
    check(c.cookie("flavour") == "chocolate", "C sees seeded cookie")
    c.close()   # OPT_COOKIEJAR flush on cleanup
    let text = slurp("/tmp/nimony-requests-autojar.txt")
    check(findSub(text, "flavour") >= 0, "cookieFile auto-flushed on close")

  if failed == 0: echo "ALL COOKIEFILE CHECKS PASSED"
  else:
    echo failed, " CHECK(S) FAILED"; quit(1)

main()
