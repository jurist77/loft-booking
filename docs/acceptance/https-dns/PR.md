# Diagnose DNS readiness without bypassing CAA

`Manage Studio HTTPS` run 42554940582 stopped at `DNS_LOOKUP_FAILED` before SSH. That log recorded neither resolver nor record type, so its original upstream response cannot be recovered retrospectively.

A public DNS-only replay on a GitHub Ubuntu runner reproduced the immediate cause: **Google HOST CAA returned HTTP 200 / DNS Status 2 (SERVFAIL)**. Google and Cloudflare both returned A records; absent AAAA was NOERROR/NODATA. Cloudflare HOST CAA and all inspected parent/TLD/root CAA queries returned NOERROR/NODATA. Initial evidence: https://github.com/jurist77/loft-booking/actions/runs/42555823749 . No SSH, Secrets or connection to the VPS was involved.

## Change

- Distinguish resolver, A/AAAA/CAA, hostname/ancestor scope, HTTP errors, DNS RCODE, timeouts, TLS, malformed JSON/schema, unexpected records, truncated replies and address mismatch.
- Record both resolvers even when one fails; Google failure cannot be overridden by Cloudflare success.
- Missing `Answer` or `[]` is valid only with NOERROR. SERVFAIL/NXDOMAIN/REFUSED/null/invalid records are never accepted as absent AAAA/CAA.
- At most two attempts for transient SERVFAIL, HTTP 429/5xx or transport/timeouts; a retry must produce a fully valid response. No DNSSEC bypass, alternate resolver or permissive CAA fallback.
- Preserve exact expected address sets on each resolver and nearest-ancestor CAA authorization, including critical flags/account restrictions.
- Write generated safe diagnostics into GitHub Summary even on failure; no names, addresses, raw responses, URLs, exception text or Secrets.
- Add manual public DNS-only inputs to existing `Check Studio HTTPS`. It has no SSH/Secrets, no VPS connection, no ACME issuance and no `apply` path. PR/push fixture tests remain mandatory. `Manage Studio HTTPS` remains main-only with its existing verified-main and SSH policy.

## Verification

Unit regression replays Google CAA SERVFAIL + Cloudflare NODATA. Additional cases cover valid missing/empty AAAA/CAA, fresh successful retry, bounded permanent failure, HTTP 403/404/429/503, timeouts, TLS/JSON/size/redirect errors, DNS status/schema/truncation, address mismatch, unexpected AAAA, CAA inheritance/critical restrictions, timeout budget, redaction and Summary emission before any SSH.

CI and subsequent live public DNS-only check results will be linked in this PR description. A red live DNS check means DNS readiness is still blocked, even if offline unit/installer/backend CI is green. Upstream SERVFAIL is not repaired by accepting it.

## Safe next step

No VPS, DNS, firewall, API protection or client UI changes. No deploy, certificate issuance, apply or merge. The failed historical request does not by itself prove a DuckDNS authoritative defect, DNSSEC issue or Google caching problem; it proves only the reproduced resolver-specific failure.

A full `Manage Studio HTTPS` run using the changed code requires owner merge because its main-only control is intentionally preserved. After owner merge and successful main CI, run **check**, never apply, and inspect both resolver/CAA results. Any required lookup failure must remain blocking.
