-- Existing recipients, bookings, outbox, invitations and update cursor stay intact.
ALTER TABLE telegram_recipients ADD COLUMN username TEXT;
ALTER TABLE telegram_recipients ADD COLUMN subscription_version INTEGER NOT NULL DEFAULT 0 CHECK(subscription_version>=0);
ALTER TABLE telegram_state ADD COLUMN worker_config TEXT CHECK(worker_config IS NULL OR length(worker_config)=64);
ALTER TABLE telegram_state ADD COLUMN last_poll_at INTEGER NOT NULL DEFAULT 0;
ALTER TABLE telegram_state ADD COLUMN owner_epoch INTEGER NOT NULL DEFAULT 0 CHECK(owner_epoch>=0);

CREATE TABLE telegram_subscription_requests (
 id TEXT PRIMARY KEY NOT NULL, recipient_id TEXT NOT NULL REFERENCES telegram_recipients(id),
 status TEXT NOT NULL CHECK(status IN ('pending','approved','rejected','cancelled','expired')),
 created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, expires_at INTEGER NOT NULL CHECK(expires_at=created_at+604800000)
) STRICT;
CREATE UNIQUE INDEX telegram_one_pending_request ON telegram_subscription_requests(recipient_id) WHERE status='pending';
CREATE TABLE telegram_bootstrap_claims (
 id TEXT PRIMARY KEY NOT NULL, recipient_id TEXT NOT NULL REFERENCES telegram_recipients(id),
 token_hash TEXT NOT NULL UNIQUE CHECK(length(token_hash)=64), created_at INTEGER NOT NULL,
 expires_at INTEGER NOT NULL CHECK(expires_at=created_at+900000), used_at INTEGER
) STRICT;
CREATE TABLE telegram_owner_transfers (
 id TEXT PRIMARY KEY NOT NULL, from_id TEXT NOT NULL REFERENCES telegram_recipients(id), to_id TEXT NOT NULL REFERENCES telegram_recipients(id),
 owner_epoch INTEGER NOT NULL, status TEXT NOT NULL CHECK(status IN ('pending','accepted','declined','expired')),
 created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL CHECK(expires_at=created_at+900000), finished_at INTEGER,
 CHECK(from_id<>to_id)
) STRICT;
CREATE UNIQUE INDEX telegram_one_owner_transfer ON telegram_owner_transfers(status) WHERE status='pending';
CREATE TABLE telegram_ui_actions (
 id TEXT PRIMARY KEY NOT NULL, actor_id TEXT NOT NULL REFERENCES telegram_recipients(id),
 kind TEXT NOT NULL, target TEXT, target_version INTEGER, owner_epoch INTEGER NOT NULL,
 created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL CHECK(expires_at=created_at+900000), used_at INTEGER
) STRICT;
CREATE TABLE telegram_interaction_limits (
 key TEXT PRIMARY KEY NOT NULL, window_at INTEGER NOT NULL, attempts INTEGER NOT NULL
) STRICT;
-- Control messages are independent of booking subscription and global pause.
-- No client booking contacts or bot token are stored in this queue.
CREATE TABLE telegram_control_outbox (
 id TEXT PRIMARY KEY NOT NULL, dedupe_key TEXT NOT NULL UNIQUE,
 recipient_id TEXT NOT NULL REFERENCES telegram_recipients(id), owner_epoch INTEGER,
 payload TEXT NOT NULL CHECK(length(payload)<=16000),
 status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','sending','sent','failed','cancelled')),
 attempts INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL, deadline_at INTEGER NOT NULL CHECK(deadline_at<=created_at+86400000),
 next_attempt_at INTEGER NOT NULL, claim_token TEXT, lease_until INTEGER, sent_at INTEGER, finished_at INTEGER, last_error TEXT,
 CHECK(last_error IS NULL OR (length(last_error)<=64 AND last_error NOT GLOB '*[^A-Z_]*'))
) STRICT;
CREATE INDEX telegram_control_due ON telegram_control_outbox(status,next_attempt_at,deadline_at);
