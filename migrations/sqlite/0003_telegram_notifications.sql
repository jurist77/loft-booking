-- No historic booking backfill. Token/configuration is NOT stored in SQLite.
CREATE TABLE telegram_recipients (
  id TEXT PRIMARY KEY NOT NULL,
  display_name TEXT NOT NULL CHECK (length(trim(display_name)) BETWEEN 1 AND 100),
  telegram_user_id TEXT UNIQUE,
  chat_id TEXT UNIQUE,
  connection_status TEXT NOT NULL DEFAULT 'invited' CHECK (connection_status IN ('invited','connected','revoked')),
  active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0,1)),
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL CHECK (updated_at >= created_at),
  CHECK (telegram_user_id IS NULL OR (length(telegram_user_id) BETWEEN 1 AND 20 AND telegram_user_id NOT GLOB '*[^0-9]*')),
  CHECK (chat_id IS NULL OR (length(chat_id) BETWEEN 1 AND 20 AND chat_id NOT GLOB '*[^0-9]*')),
  CHECK (connection_status != 'connected' OR (telegram_user_id IS NOT NULL AND chat_id IS NOT NULL))
) STRICT;

CREATE TABLE telegram_state (
  id INTEGER PRIMARY KEY CHECK (id=1),
  enabled INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0,1)),
  owner_recipient_id TEXT REFERENCES telegram_recipients(id),
  bot_id TEXT, bot_username TEXT,
  update_offset INTEGER NOT NULL DEFAULT 0 CHECK (update_offset >= 0),
  worker_owner TEXT, worker_until INTEGER NOT NULL DEFAULT 0,
  next_send_at INTEGER NOT NULL DEFAULT 0,
  last_error TEXT, last_error_at INTEGER
) STRICT;
INSERT INTO telegram_state(id) VALUES (1);

CREATE TABLE telegram_invitations (
  token_hash TEXT PRIMARY KEY NOT NULL CHECK (length(token_hash)=64),
  recipient_id TEXT NOT NULL REFERENCES telegram_recipients(id),
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL CHECK (expires_at > created_at AND expires_at <= created_at+86400000),
  used_at INTEGER, revoked_at INTEGER
) STRICT;
CREATE UNIQUE INDEX telegram_one_live_invite ON telegram_invitations(recipient_id)
  WHERE used_at IS NULL AND revoked_at IS NULL;

CREATE TABLE telegram_invite_limits (
  sender_hash TEXT PRIMARY KEY NOT NULL, window_at INTEGER NOT NULL, attempts INTEGER NOT NULL
) STRICT;

CREATE TABLE telegram_outbox (
  id TEXT PRIMARY KEY NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('booking','test')),
  booking_id TEXT REFERENCES bookings(id),
  recipient_id TEXT NOT NULL REFERENCES telegram_recipients(id),
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','sending','sent','failed','cancelled')),
  attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  created_at INTEGER NOT NULL,
  deadline_at INTEGER NOT NULL CHECK (deadline_at=created_at+86400000),
  next_attempt_at INTEGER NOT NULL,
  claim_token TEXT, lease_until INTEGER,
  sent_at INTEGER, finished_at INTEGER,
  last_error TEXT,
  CHECK ((kind='booking' AND booking_id IS NOT NULL) OR (kind='test' AND booking_id IS NULL)),
  CHECK (last_error IS NULL OR (length(last_error) <= 64 AND last_error NOT GLOB '*[^A-Z_]*'))
) STRICT;
CREATE UNIQUE INDEX telegram_booking_recipient ON telegram_outbox(booking_id,recipient_id) WHERE kind='booking';
CREATE INDEX telegram_outbox_due ON telegram_outbox(status,next_attempt_at,deadline_at);

CREATE TRIGGER bookings_telegram_outbox AFTER INSERT ON bookings WHEN NEW.status='confirmed'
BEGIN
  INSERT INTO telegram_outbox(id,kind,booking_id,recipient_id,created_at,deadline_at,next_attempt_at)
  SELECT lower(hex(randomblob(16))),'booking',NEW.id,id,NEW.created_at,NEW.created_at+86400000,NEW.created_at
  FROM telegram_recipients WHERE active=1 AND connection_status='connected';
END;

CREATE TRIGGER telegram_recipient_stop AFTER UPDATE OF active,connection_status,chat_id ON telegram_recipients
WHEN NEW.active=0 OR NEW.connection_status!='connected' OR (OLD.chat_id IS NOT NULL AND OLD.chat_id IS NOT NEW.chat_id)
BEGIN
  UPDATE telegram_outbox SET status='cancelled',last_error='RECIPIENT_DISABLED',finished_at=NEW.updated_at,
    claim_token=NULL,lease_until=NULL WHERE recipient_id=NEW.id AND status IN ('pending','sending');
END;

CREATE TRIGGER bookings_telegram_cancel AFTER UPDATE OF status ON bookings WHEN NEW.status='cancelled'
BEGIN
  UPDATE telegram_outbox SET status='cancelled',last_error='BOOKING_CANCELLED',finished_at=NEW.updated_at,
    claim_token=NULL,lease_until=NULL WHERE booking_id=NEW.id AND status IN ('pending','sending');
END;
