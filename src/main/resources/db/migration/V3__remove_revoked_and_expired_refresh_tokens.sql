DELETE FROM refresh_tokens
WHERE revoked = TRUE OR expires_at <= CURRENT_TIMESTAMP;
