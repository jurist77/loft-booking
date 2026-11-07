# Fix installer SSH stdin descriptor

The first `Peer.info()` fails before SSH starts: `Peer.call()` passes `BytesIO` as `Popen(stdin=...)`, whose `fileno()` raises `UnsupportedOperation`. The generic OSError handler incorrectly reports `SSH_TIMEOUT_OR_TRANSPORT_FAILED`.

Use an anonymous private `TemporaryFile` containing installer source, rewind it before launch, keep it open through `communicate()`, and close it on every exit. It contains no password or customer data. Unsupported local streams now report `SSH_STREAM_UNSUPPORTED`. Close Popen-owned stdout/stderr pipes on timeout as well as reaping the child; caller-owned input/output files retain their existing ownership.

Six regressions use real local Popen (only SSH argv is substituted): initial info, daily/pre-update binary backup, restore info + pre-restore backup + framed upload, failure cleanup, timeout cleanup, and unsupported-stream diagnosis. They check full source/EOF, payload hashes, mode0600, closed descriptors and reaped children. Existing transport mocks alone could not catch this defect. All 57 installer tests pass locally, without ResourceWarning.

The existing Installer CI runs these tests plus native package/systemd checks on Ubuntu24.04 x64 and ARM64 after this PR opens. CI results must refer to this branch's exact SHA; no success on those architectures is claimed before the runs finish.

No changes to VPS Manager, application/UI/SQLite schema, existing VPS services, SSH configuration/options, deployment architecture, workflows or paid dependencies. No real SSH/VPS install or working backup-repository operations were performed. Do not merge automatically.
