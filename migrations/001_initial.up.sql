CREATE TABLE IF NOT EXISTS download_records (
    id             TEXT NOT NULL PRIMARY KEY,
    principal_label TEXT,
    ecosystem      TEXT NOT NULL,
    package_name   TEXT NOT NULL,
    version        TEXT NOT NULL,
    outcome        TEXT NOT NULL CHECK (outcome IN ('allowed','blocked')),
    block_reason   TEXT,
    policy_version INTEGER,
    client_ip      TEXT,
    user_agent     TEXT,
    occurred_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_dr_pkg    ON download_records (ecosystem, package_name, version, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_dr_label  ON download_records (principal_label, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_dr_outcome ON download_records (outcome, occurred_at DESC);
