# Studio HTTPS: provider-independent hostname / CAA acceptance

PR: https://github.com/jurist77/loft-booking/pull/21

## Changes and boundaries

The shared managed transport validator accepts canonical ASCII FQDNs, including dynv6 and the previous DuckDNS names. It rejects URLs, IP literals, wildcards, invalid labels, local/special-use names and noncanonical spellings. Hostname/IP are runtime inputs, not algorithm constants.

Required and diagnostic CAA lookups share one closest-first hierarchy generator: every parent label through TLD and root. Both Google and Cloudflare must succeed independently. The nearest nonempty RRset governs issuance; diagnostic ancestors cannot override it or repair a failed required lookup. CD=false is explicit; SERVFAIL, IP mismatch, disabled checking and unexpected/alias answers still fail closed. Raw DNSSEC records are not requested: DO controls RR delivery, not recursive validation.

No changes to exact API Origin, proxy trust, loopback cutover, booking rules, UI, DEMO or restrictions on changing an already managed HTTPS hostname. Monitor and install/update/backup/restore reuse the same validator. Real TLS/browser/recovery lifecycle CI now uses a non-DuckDNS synthetic name with an isolated CA and SQLite.

## Public DNS evidence (9 November 2026)

Production-code DNS-only check: https://github.com/jurist77/loft-booking/actions/runs/42598430254

Independent authoritative observations: https://github.com/jurist77/loft-booking/actions/runs/42598621783

The latter is an isolated analysis branch, not code proposed by this PR; only DNS QUERY operations, no SSH, Secrets, VPS requests, ACME orders or DNS changes. There are 37 structured observations, including repeat authoritative queries, not 37 acceptance tests.

| Check | Observed result |
|---|---|
| `studio1925.dynv6.net` A, Google and Cloudflare | NOERROR, exact match to expected IPv4 `2.27.207.130` |
| AAAA, both resolvers | NOERROR/NODATA; no IPv6 published |
| CAA at hostname, dynv6.net, net and root, both resolvers | NOERROR/NODATA; no prohibiting policy found |
| Authoritative ns1/ns2/ns3.dynv6.com, UDP and TCP | AA=1; A matches expected IPv4; AAAA and CAA return NOERROR/NODATA |

No external DNS error was observed in these measurements. They differ from the previous DuckDNS A-in-CAA defect. These are time-bounded DNS facts, not proof of VPS admission, external ACME reachability, issued TLS or future renewal.

## Automated verification

- Local HTTPS suite: 43 tests pass, including old DuckDNS failure regression and new arbitrary-depth CAA/FQDN/DNSSEC cases.
- Local installer suite: 66 tests pass, including non-DuckDNS HTTPS metadata / backup / restore / no-downgrade behavior.
- Python compilation, changed workflow YAML parsing and `git diff --check` pass.
- Required final-SHA CI results are linked in the PR checks: HTTPS fixtures x64/ARM64, native installer x64/ARM64 (real Caddy/browser/SQLite/recovery/update/restore), Backend CI, network/firewall/audit fixtures. Do not infer final-SHA success from an older run.
- Real VPS / Let's Encrypt issuance: NOT RUN. No apply, deployment, merge, firewall/DNS/SSH/service change or production booking.

## Safe next check after owner review and merge

Wait for successful checks on the new main, then Actions → **Manage Studio HTTPS** → Run workflow:

| Input | Value |
|---|---|
| Branch | main |
| server_ip | 2.27.207.130 |
| hostname | studio1925.dynv6.net |
| additional_ip | empty |
| mode | check |
| confirmation | empty |

Manage remains main-only and is not run by this PR. A successful check does not authorize apply. Existing network/firewall/ownership gates remain; if they fail, diagnose separately. Changing an already committed HTTPS hostname remains an explicit-review operation. No DNS provider token or new Secret is required for HTTP-01.
