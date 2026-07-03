CREATE TABLE IF NOT EXISTS psychologists (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  name           TEXT NOT NULL,
  email          TEXT NOT NULL,
  city           TEXT,
  specialization TEXT,
  experience_years INTEGER,
  has_certificate INTEGER DEFAULT 0,  -- 0/1
  created_at     TEXT NOT NULL DEFAULT (datetime('now')),
  ip_hash        TEXT,
  source         TEXT DEFAULT 'for-psychologists'
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_psychologists_email ON psychologists (email);
CREATE INDEX IF NOT EXISTS idx_psychologists_ip_hash ON psychologists (ip_hash, created_at);
