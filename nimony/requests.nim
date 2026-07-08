## `requests` — a browser-impersonating HTTP client for nimony.
##
## Umbrella module: import this to get the FFI, the impersonation profiles, the
## Session/Response client surface, and every feature module in one namespace.
##
##   import requests
##   let s = newSession("chrome136")
##   let r = s.get("https://httpbin.org/get")
##   echo r.status, " ", r.body.len
##   s.close()
##
## See requests/PORTING-NOTES.md for the nimony-idiom notes and the Nim2 origin.

import requests/ffi
import requests/profiles
import requests/client
import requests/util
import requests/headers
import requests/tls
import requests/proxy
import requests/coherence
import requests/cookies
import requests/cookiejar
import requests/share
import requests/multi

export ffi
export profiles
export client
export util
export headers
export tls
export proxy
export coherence
export cookies
export cookiejar
export share
export multi
