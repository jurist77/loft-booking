-- Extend the applied foundation; preserve old intervals and unknown legacy contacts/timestamps.
CREATE TABLE resources (
  id TEXT PRIMARY KEY NOT NULL,
  name TEXT NOT NULL CHECK (length(trim(name)) BETWEEN 1 AND 100)
) STRICT;
INSERT INTO resources (id, name) VALUES ('studio-19-25', 'studio 19.25');

DROP TRIGGER bookings_no_overlap_insert;
DROP TRIGGER bookings_no_overlap_update;
DROP INDEX bookings_active_interval;
ALTER TABLE bookings RENAME TO bookings_v1;

CREATE TABLE bookings (
  id TEXT PRIMARY KEY NOT NULL,
  resource_id TEXT NOT NULL REFERENCES resources(id) ON DELETE RESTRICT,
  starts_at INTEGER NOT NULL,
  ends_at INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'confirmed' CHECK (status IN ('confirmed', 'cancelled')),
  first_name TEXT CHECK (first_name IS NULL OR length(trim(first_name)) BETWEEN 1 AND 80),
  last_name TEXT CHECK (last_name IS NULL OR length(trim(last_name)) BETWEEN 1 AND 80),
  phone TEXT CHECK (phone IS NULL OR (length(phone) = 12 AND substr(phone, 1, 3) = '+79' AND substr(phone, 2) NOT GLOB '*[^0-9]*')),
  created_at INTEGER CHECK (created_at IS NULL OR created_at >= 0),
  updated_at INTEGER CHECK (updated_at IS NULL OR updated_at >= 0),
  CHECK (created_at IS NULL OR (updated_at IS NOT NULL AND updated_at >= created_at)),
  CHECK (ends_at - starts_at >= 3600000),
  CHECK (starts_at % 1800000 = 0 AND ends_at % 1800000 = 0),
  CHECK (starts_at >= 0 AND ends_at <= 253402300799000),
  CHECK (date(starts_at / 1000, 'unixepoch', '+3 hours') = date(ends_at / 1000, 'unixepoch', '+3 hours')),
  CHECK (CAST(strftime('%H', starts_at / 1000, 'unixepoch', '+3 hours') AS INTEGER) >= 9),
  CHECK (CAST(strftime('%H', ends_at / 1000, 'unixepoch', '+3 hours') AS INTEGER) < 23 OR
    strftime('%H:%M', ends_at / 1000, 'unixepoch', '+3 hours') = '23:00')
) STRICT;

INSERT INTO bookings (id, resource_id, starts_at, ends_at, status)
SELECT id, 'studio-19-25', starts_at, ends_at, status FROM bookings_v1;
DROP TABLE bookings_v1;
CREATE INDEX bookings_active_interval ON bookings(resource_id, starts_at, ends_at) WHERE status = 'confirmed';

CREATE TABLE booking_events (
  id INTEGER PRIMARY KEY,
  booking_id TEXT NOT NULL REFERENCES bookings(id) ON DELETE RESTRICT,
  event_type TEXT NOT NULL CHECK (event_type IN ('created', 'cancelled')),
  occurred_at INTEGER NOT NULL CHECK (occurred_at >= 0)
) STRICT;
CREATE INDEX booking_events_by_booking ON booking_events(booking_id, id);
CREATE UNIQUE INDEX booking_one_created_event ON booking_events(booking_id) WHERE event_type = 'created';

-- Only migrated rows may have unknown contacts/creation time. New inserts must be complete.
CREATE TRIGGER bookings_require_details BEFORE INSERT ON bookings
WHEN NEW.first_name IS NULL OR NEW.last_name IS NULL OR NEW.phone IS NULL OR NEW.created_at IS NULL OR NEW.updated_at IS NULL
BEGIN SELECT RAISE(ABORT, 'BOOKING_DETAILS_REQUIRED'); END;
CREATE TRIGGER bookings_preserve_details BEFORE UPDATE ON bookings
WHEN (OLD.first_name IS NOT NULL AND NEW.first_name IS NULL)
  OR (OLD.last_name IS NOT NULL AND NEW.last_name IS NULL)
  OR (OLD.phone IS NOT NULL AND NEW.phone IS NULL)
  OR (OLD.created_at IS NOT NULL AND NEW.created_at IS NULL)
  OR (OLD.updated_at IS NOT NULL AND NEW.updated_at IS NULL)
BEGIN SELECT RAISE(ABORT, 'BOOKING_DETAILS_REQUIRED'); END;

CREATE TRIGGER bookings_no_overlap_insert BEFORE INSERT ON bookings
WHEN NEW.status = 'confirmed' AND EXISTS (
  SELECT 1 FROM bookings WHERE resource_id = NEW.resource_id AND status = 'confirmed'
    AND starts_at < NEW.ends_at AND ends_at > NEW.starts_at
)
BEGIN SELECT RAISE(ABORT, 'BOOKING_OVERLAP'); END;
CREATE TRIGGER bookings_no_overlap_update BEFORE UPDATE OF resource_id, starts_at, ends_at, status ON bookings
WHEN NEW.status = 'confirmed' AND EXISTS (
  SELECT 1 FROM bookings WHERE resource_id = NEW.resource_id AND status = 'confirmed' AND id <> OLD.id
    AND starts_at < NEW.ends_at AND ends_at > NEW.starts_at
)
BEGIN SELECT RAISE(ABORT, 'BOOKING_OVERLAP'); END;

CREATE TRIGGER bookings_cancel_requires_timestamp BEFORE UPDATE OF status ON bookings
WHEN OLD.status = 'confirmed' AND NEW.status = 'cancelled' AND NEW.updated_at IS NULL
BEGIN SELECT RAISE(ABORT, 'BOOKING_TIMESTAMP_REQUIRED'); END;
CREATE TRIGGER bookings_created_event AFTER INSERT ON bookings
BEGIN
  INSERT INTO booking_events(booking_id, event_type, occurred_at) VALUES (NEW.id, 'created', NEW.created_at);
END;
CREATE TRIGGER bookings_cancelled_event AFTER UPDATE OF status ON bookings
WHEN OLD.status = 'confirmed' AND NEW.status = 'cancelled'
BEGIN
  INSERT INTO booking_events(booking_id, event_type, occurred_at) VALUES (NEW.id, 'cancelled', NEW.updated_at);
END;
