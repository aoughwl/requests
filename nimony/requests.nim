## `requests` — a browser-impersonating HTTP client for nimony.
##
## Umbrella module: import this to get the FFI, the impersonation profiles, the
## Session/Response client surface, and the convenience helpers (auth/forms/query)
## in one namespace.
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

export ffi
export profiles
export client
export util
