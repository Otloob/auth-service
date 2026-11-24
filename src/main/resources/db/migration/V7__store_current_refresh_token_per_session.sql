-- Recreate dev refresh-session storage: one current token hash per device session.
DROP TABLE IF EXISTS refresh_tokens;

CREATE TABLE refresh_tokens (
    session_id VARCHAR(36) PRIMARY KEY,
    token_hash VARCHAR(64) NOT NULL,
    user_id BIGINT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    expires_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    device_name VARCHAR(100)
);

CREATE INDEX ix_refresh_tokens_user_id ON refresh_tokens (user_id);
CREATE INDEX ix_refresh_tokens_expires_at ON refresh_tokens (expires_at);
