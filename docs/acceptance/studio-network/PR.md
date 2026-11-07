# feat: add manual read-only Studio network diagnostic

Adds `Diagnose Studio network` (workflow_dispatch only, input server_ip, main guard) using the existing STUDIO_SSH_PASSWORD Secret and Studio root:22 SSH policy. It never installs/repairs/restarts anything on the VPS. The real diagnostic was not run.

The probe reads selected Studio service properties, TCP binds at3000/Studio MainPID, local health, and UFW/nftables/iptables summaries. The runner independently checks IP:3000 health. Raw rules, VPN configs, journals, PIDs/process names/peer addresses, HTTP bodies/headers and credentials are omitted. Only controlled typed fields pass the runner schema. Missing tools, bounded-output/timeouts and complex rules remain uncertainty, not a claim that ports are open. A health response from another process does not confirm Studio.

All subprocess argv are fixed read-only allowlists; no shell on the host probe, no configuration/file writes or installer state lock. The probe is streamed via private FD and isolated Python -I -B -S. Per-command output/deadline limits and HTTP size/deadline limits apply; redirects are not followed. Existing SSH host-key verification remains disabled by owner agreement: MITM/root-password theft and falsified reports remain risks.

Adds fixture-only `Check Studio network diagnostic` CI and 16 tests: redaction, read-only contract, service/bind/family/port/ownership/health causes, firewall summaries, unsupported tools, malicious JSON, safe input, actual local child cleanup and local fixture HTTP GET/redirect/timeout. No real SSH, VPS, firewall query or working backup repo is used by tests.

No changes to deployment/installer behaviour, Studio UI/API/SQLite, existing VPN/services/network settings or other workflows. No merge or real diagnostics performed. Details/interpretation: docs/studio-network-diagnostics.md. Successful execution means report produced, not successful deployment or healthy booking flow.
