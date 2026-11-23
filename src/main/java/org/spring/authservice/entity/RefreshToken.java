package org.spring.authservice.entity;

import java.time.Instant;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.Column;

@Entity
@Table(name = "refresh_tokens")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class RefreshToken {
    @Id private String tokenId;
    @Column(length = 64)
    private String tokenHash;
    private Long userId;
    @Column(length = 36)
    private String sessionId;
    @Column(length = 100)
    private String deviceName;
    private Instant expiresAt;
    private boolean revoked;
    public RefreshToken(String tokenId, String tokenHash, Long userId, String sessionId, String deviceName, Instant expiresAt) {
        this.tokenId = tokenId;
        this.tokenHash = tokenHash;
        this.userId = userId;
        this.sessionId = sessionId;
        this.deviceName = deviceName;
        this.expiresAt = expiresAt;
    }
    public void revoke() { revoked = true; }
    public void setTokenHash(String tokenHash) { this.tokenHash = tokenHash; }
}
