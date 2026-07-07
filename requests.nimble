# Package
version       = "0.1.0"
author        = "savannt"
description    = "State-of-the-art browser-impersonating HTTP client for Nimony (TLS/JA3/JA4 + HTTP/2 fingerprint matching via curl-impersonate / BoringSSL)"
license        = "MIT"
srcDir         = "src"

# Dependencies
requires "nim >= 2.0.0"

# Notes:
#   This package FFIs against libcurl-impersonate (BoringSSL build), NOT stock
#   libcurl. Stock libcurl is OpenSSL-backed and produces a non-browser JA3.
#   Run `scripts/fetch_curl_impersonate.sh` first to install the prebuilt lib,
#   or point WRAITH_CURL_LIB at your own build. See README.md.

task selfcheck, "Compile + run the fingerprint self-check (proves TLS/H2 indistinguishability)":
  exec "nim c -r --threads:on tests/test_fingerprint.nim"
