## `requests` - an HTTP client for the aoughwl stack: native (tcp/net/tls) by default, browser-impersonating via libcurl-impersonate on request.
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
## See docs/PORTING-NOTES.md for the idiom notes and the Nim 2 origin (branch nim2).

import requests/ffi
import requests/profiles
import requests/client
import requests/util
import requests/headers
import requests/tlsoverrides
import requests/proxy
import requests/coherence
import requests/cookies
import requests/cookiejar
import requests/certinfo
import requests/share
import requests/multi

export ffi
export profiles
export client
export util
export headers
export tlsoverrides
export proxy
export coherence
export cookies
export cookiejar
export certinfo
export share
export multi
