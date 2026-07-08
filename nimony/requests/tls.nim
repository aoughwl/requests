## TLS / fingerprint override builders — with a LOUD coherence warning (nimony).
##
## The profile owns your JA3/JA4. These helpers override curl's TLS behaviour ON
## TOP of the profile for the cases that need it (a MITM proxy with a private CA,
## a self-signed test host, mutual-TLS client certs). Two of them — custom cipher
## lists and a pinned TLS min — CHANGE the ClientHello and BREAK the fingerprint.
## `auditTls` flags exactly those; the CA / verify / client-cert knobs are safe.

import requests/client

# ── fingerprint-SAFE builders (don't touch the ClientHello) ─────────────────

proc insecureTls*(): TlsConfig =
  ## Disable peer + host verification — for a MITM proxy or self-signed host
  ## DURING TESTING. Never ship this against real targets.
  result = TlsConfig()
  result.verifyPeer = triOff
  result.verifyHost = triOff

proc withCA*(caInfo = "", caPath = ""): TlsConfig =
  ## Trust a custom CA bundle file and/or directory (e.g. your proxy's root).
  result = TlsConfig()
  result.caInfo = caInfo
  result.caPath = caPath

proc withClientCert*(cert: string, key: string, password = "",
                     certType = "PEM"): TlsConfig =
  ## Present a client certificate (mutual TLS). `certType` is PEM/DER/P12.
  result = TlsConfig()
  result.clientCert = cert
  result.clientKey = key
  result.keyPassword = password
  result.clientCertType = certType

proc withAlpn*(on: bool): TlsConfig =
  ## Toggle ALPN explicitly (rarely needed; the profile sets it).
  result = TlsConfig()
  result.alpn = if on: triOn else: triOff

# ── fingerprint-BREAKING builders (audit will warn) ─────────────────────────

proc customCiphers*(tls12List: string, tls13List = ""): TlsConfig =
  ## Override the cipher/ciphersuite lists. WARNING: rewrites the ClientHello and
  ## breaks JA3/JA4 coherence — `auditTls` flags it.
  result = TlsConfig()
  result.cipherList = tls12List
  result.tls13Ciphers = tls13List

proc pinTlsVersion*(minVer = 0, maxVer = 0): TlsConfig =
  ## Pin the TLS min/max (SSLVERSION_* / SSLVERSION_MAX_*). WARNING: pinning the
  ## MIN drops supported_versions entries and breaks the fingerprint — `auditTls`
  ## flags a non-zero min.
  result = TlsConfig()
  result.sslVersionMin = minVer
  result.sslVersionMax = maxVer

proc withTls*(cfg: RequestConfig, tls: TlsConfig): RequestConfig =
  ## Attach a TlsConfig to a RequestConfig (fluent composition).
  result = cfg
  result.tls = tls

proc tlsConfig*(tls: TlsConfig): RequestConfig =
  ## A RequestConfig carrying just this TlsConfig.
  result = RequestConfig()
  result.tls = tls

# ── coherence linter for TLS overrides ──────────────────────────────────────

proc auditTls*(cfg: RequestConfig): seq[string] =
  ## Warnings for any TLS override that would break the impersonated
  ## fingerprint. Empty ⇒ the ClientHello is still the profile's.
  result = @[]
  if cfg.tls.cipherList.len > 0:
    result.add "TLS cipherList override rewrites the ClientHello — JA3/JA4 no longer match the profile"
  if cfg.tls.tls13Ciphers.len > 0:
    result.add "TLS 1.3 ciphersuite override rewrites the ClientHello — JA3/JA4 no longer match the profile"
  if cfg.tls.sslVersionMin != 0:
    result.add "pinning the TLS MIN version drops supported_versions entries and breaks the fingerprint"
