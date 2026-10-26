ALTER TABLE refresh_tokens
    ADD COLUMN IF NOT EXISTS session_id VARCHAR(36);

ALTER TABLE refresh_tokens
    ADD COLUMN IF NOT EXISTS device_name VARCHAR(100);

CREATE UNIQUE INDEX IF NOT EXISTS ux_users_email ON users (email);
CREATE INDEX IF NOT EXISTS ix_refresh_tokens_session_id ON refresh_tokens (session_id);
