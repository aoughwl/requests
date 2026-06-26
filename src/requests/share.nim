## Cross-session / cross-thread shared state — the scaling primitive.
##
## A `Session` owns ONE curl handle, which is not thread-safe. To scrape at
## throughput you want many sessions on many threads that STILL behave like one
## browser: a single cookie jar, one DNS cache, a shared TLS-session cache (so
## resumption works across handles) and one connection pool (so HTTP/2 requests
## coalesce instead of each thread opening its own connection).
##
## That is exactly what curl's share interface (CURLSH) provides. Cross-thread
## access to the shared data is serialized by the lock callbacks below, so it is
## safe to hand one `Share` to a pool of sessions on different threads.
##
##   let pool = newShare()                  # cookies+DNS+TLS+connections shared
##   # ...on each worker thread:
##   let s = newSession("chrome136", share = pool)
##   ...
##   pool.close()                           # AFTER every session is closed
##
## Build threaded programs with `--threads:on`.

import std/locks
import ./ffi

type
  Share* = ref object
    handle*: CURLSH
    locks: ptr array[LOCK_DATA_COUNT, Lock]   # heap ⇒ stable address for the cb

# curl hands us a CURL_LOCK_DATA_* id; we take a per-resource lock so different
# resources don't contend. `access` (shared vs single) is ignored — a plain
# mutex per resource is correct, just slightly more conservative.
proc lockCb(handle: CURL, data: cint, access: cint, userptr: pointer) {.cdecl.} =
  let locks = cast[ptr array[LOCK_DATA_COUNT, Lock]](userptr)
  if data >= 0 and data < LOCK_DATA_COUNT:
    acquire(locks[][data])

proc unlockCb(handle: CURL, data: cint, userptr: pointer) {.cdecl.} =
  let locks = cast[ptr array[LOCK_DATA_COUNT, Lock]](userptr)
  if data >= 0 and data < LOCK_DATA_COUNT:
    release(locks[][data])

proc newShare*(cookies = true, dns = true, tlsSessions = true,
               connections = true): Share =
  ## A pool of browser-coherent state for any number of sessions/threads.
  ## Each flag toggles one shared resource. The returned `Share` must outlive
  ## every session attached to it and be `close`d only after they are.
  let h = curl_share_init()
  if h.isNil: raise newException(IOError, "curl_share_init failed")

  let locks = create(array[LOCK_DATA_COUNT, Lock])
  for i in 0 ..< LOCK_DATA_COUNT: initLock(locks[][i])

  discard curl_share_setopt(h, SHOPT_LOCKFUNC, lockCb)
  discard curl_share_setopt(h, SHOPT_UNLOCKFUNC, unlockCb)
  discard curl_share_setopt(h, SHOPT_USERDATA, locks)
  if cookies:     discard curl_share_setopt(h, SHOPT_SHARE, clong(LOCK_DATA_COOKIE))
  if dns:         discard curl_share_setopt(h, SHOPT_SHARE, clong(LOCK_DATA_DNS))
  if tlsSessions: discard curl_share_setopt(h, SHOPT_SHARE, clong(LOCK_DATA_SSL_SESSION))
  if connections: discard curl_share_setopt(h, SHOPT_SHARE, clong(LOCK_DATA_CONNECT))

  result = Share(handle: h, locks: locks)

proc close*(sh: Share) =
  ## Tear the share down. ALL sessions attached to it must already be closed.
  if not sh.handle.isNil:
    discard curl_share_cleanup(sh.handle)
    sh.handle = nil
  if sh.locks != nil:
    for i in 0 ..< LOCK_DATA_COUNT: deinitLock(sh.locks[][i])
    dealloc(sh.locks)
    sh.locks = nil
