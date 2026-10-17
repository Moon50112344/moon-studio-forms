
CREATE TABLE IF NOT EXISTS surveys (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    ends_at INTEGER DEFAULT NULL,
    destination_url TEXT NOT NULL,
    is_published INTEGER NOT NULL DEFAULT 1
        CHECK (is_published IN (0, 1)),
    created_on INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_on INTEGER NOT NULL DEFAULT (unixepoch()),
    CHECK (length(title) BETWEEN 1 AND 200),
    CHECK (length(description) <= 3000),
    CHECK (ends_at IS NULL OR ends_at > 0)
);

CREATE INDEX IF NOT EXISTS idx_surveys_published
ON surveys (is_published, created_on DESC);

CREATE INDEX IF NOT EXISTS idx_surveys_created_at
ON surveys (created_at DESC);

CREATE TABLE IF NOT EXISTS admin_sessions (
    token_hash TEXT PRIMARY KEY,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    expires_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_admin_sessions_expiry
ON admin_sessions (expires_at);
