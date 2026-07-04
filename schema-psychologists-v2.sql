-- D1 migration v2: add status, bio, website to psychologists
ALTER TABLE psychologists ADD COLUMN status TEXT NOT NULL DEFAULT 'pending';
ALTER TABLE psychologists ADD COLUMN bio TEXT;
ALTER TABLE psychologists ADD COLUMN website TEXT;

CREATE INDEX IF NOT EXISTS idx_psychologists_status ON psychologists (status);
