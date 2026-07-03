-- D1 migration: email subscribers
CREATE TABLE IF NOT EXISTS subscribers (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  email      TEXT    NOT NULL,
  created_at TEXT    NOT NULL DEFAULT (datetime('now')),
  ip_hash    TEXT,
  source     TEXT    DEFAULT 'index'
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_subscribers_email
  ON subscribers (email);

-- for rate-limit query: count by ip_hash in last 24h
CREATE INDEX IF NOT EXISTS idx_subscribers_ip_hash_created
  ON subscribers (ip_hash, created_at);
