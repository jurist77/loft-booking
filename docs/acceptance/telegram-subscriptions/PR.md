## Telegram subscriptions and owner management

Studio already has a SQLite notification outbox and a long-polling worker. This change adds employee subscription requests and owner management through Telegram buttons, and private initial configuration through a main-only Manage Studio Telegram workflow. The booking interface, booking rules, installer and HTTPS implementation remain unchanged.

Owner authority is separate from booking subscription. Decisions check the current SQLite owner and use actor-bound, signed, expiring, single-use callbacks. Ownership transfer requires both current and prospective owners. Bootstrap requires an account-bound private bot challenge and explicit confirmation through a temporary GitHub Secret; Start never grants privileges.

Tokens are verified with getMe and webhook checks before an atomic private configuration replacement; rotation accepts only the same bot ID and preserves users, queue and signing key. Success requires live polling of the current configuration. Host binding plus serialized GitHub Deployment metadata prevent supported setup/restore workflows from activating the same token on independent VPS copies; a deliberate host move requires BotFather token rotation. No app deploy occurs here.

### Validation

Local: 165 unit, 97 real SQLite integration, 89 installer/security, 88 HTTPS, 11 VPS-audit, 45 firewall fixtures; six kernel-only firewall cases require the existing isolated Ubuntu CI. SERVER build, API HTTP19, repeated health recovery and permanent-failure control, TypeScript, lint, Node/static DEMO isolation/audit, SERVER browser40 and static DEMO browser26 passed. Telegram transport is substituted; no actual bot/VPS messages or production data.

Required CI retains Backend, native Installer x64/ARM64 (including browser/Caddy/systemd/update/restore/rollback), HTTPS/kernel x64/ARM64 and VPS Audit. Final results must be verified on this PR's final SHA in Checks.

Migration0004 is additive; applied0001–0003 and existing bookings are preserved. Encrypted settings backup retains the v2 token/key, while restored configuration cannot poll automatically. Because the existing restore swaps the entire DATA directory, reactivation after restore on the same or a different VPS requires BotFather token rotation and rotate-token; normal updates retain the host binding. No merge/deploy, Caddy/UFW/DNS/SSH/VPN changes, new service, public admin endpoint or web admin panel.

Runbook/security limitations: docs/telegram-notifications.md. Acceptance and test coverage: docs/acceptance/telegram-subscriptions/README.md. Production activation and legal basis for sending customer contacts to Telegram require separate owner approval. Telegram cannot guarantee exactly-once or recall already accepted messages; root/manual copies outside these repository workflows cannot be globally coordinated.
