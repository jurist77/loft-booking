CREATE TABLE _health (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  counter INTEGER NOT NULL DEFAULT 0
) STRICT;
INSERT INTO _health (id) VALUES (1);

-- SQL-only foundation; no booking API, contacts or real availability source yet.
-- UTC epoch milliseconds. Moscow is UTC+3 without DST for the supported dates.
CREATE TABLE bookings (
  id TEXT PRIMARY KEY NOT NULL,
  starts_at INTEGER NOT NULL,
  ends_at INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'confirmed' CHECK (status IN ('confirmed', 'cancelled')),
  CHECK (ends_at - starts_at >= 3600000),
  CHECK (starts_at % 1800000 = 0 AND ends_at % 1800000 = 0),
  CHECK (starts_at >= 0 AND ends_at <= 253402300799000),
  CHECK (date(starts_at / 1000, 'unixepoch', '+3 hours') = date(ends_at / 1000, 'unixepoch', '+3 hours')),
  CHECK (CAST(strftime('%H', starts_at / 1000, 'unixepoch', '+3 hours') AS INTEGER) >= 9),
  CHECK (CAST(strftime('%H', ends_at / 1000, 'unixepoch', '+3 hours') AS INTEGER) < 23 OR
    strftime('%H:%M', ends_at / 1000, 'unixepoch', '+3 hours') = '23:00')
) STRICT;
CREATE INDEX bookings_active_interval ON bookings(starts_at, ends_at) WHERE status = 'confirmed';

CREATE TRIGGER bookings_no_overlap_insert BEFORE INSERT ON bookings
WHEN NEW.status = 'confirmed' AND EXISTS (
  SELECT 1 FROM bookings WHERE status = 'confirmed'
    AND starts_at < NEW.ends_at AND ends_at > NEW.starts_at
)
BEGIN SELECT RAISE(ABORT, 'BOOKING_OVERLAP'); END;

CREATE TRIGGER bookings_no_overlap_update BEFORE UPDATE OF starts_at, ends_at, status ON bookings
WHEN NEW.status = 'confirmed' AND EXISTS (
  SELECT 1 FROM bookings WHERE status = 'confirmed' AND id <> OLD.id
    AND starts_at < NEW.ends_at AND ends_at > NEW.starts_at
)
BEGIN SELECT RAISE(ABORT, 'BOOKING_OVERLAP'); END;
