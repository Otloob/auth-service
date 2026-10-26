package org.spring.authservice.token;

import java.time.Instant;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "refresh_tokens")
public class RefreshToken {
    @Id private String tokenId;
    private Long userId;
    private Instant expiresAt;
    private boolean revoked;
    protected RefreshToken() {}
    public RefreshToken(String tokenId, Long userId, Instant expiresAt) { this.tokenId = tokenId; this.userId = userId; this.expiresAt = expiresAt; }
    public String getTokenId() { return tokenId; }
    public Long getUserId() { return userId; }
    public Instant getExpiresAt() { return expiresAt; }
    public boolean isRevoked() { return revoked; }
    public void revoke() { revoked = true; }
}
