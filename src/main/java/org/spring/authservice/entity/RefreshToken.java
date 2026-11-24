package org.spring.authservice.entity;

import java.time.Instant;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "refresh_tokens")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class RefreshToken {
    @Id
    @Column(name = "session_id", length = 36)
    private String sessionId;

    @Column(name = "token_hash", length = 64, nullable = false)
    private String tokenHash;

    @Column(name = "user_id", nullable = false)
    private Long userId;

    @Column(name = "device_name", length = 100)
    private String deviceName;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    public RefreshToken(String sessionId, String tokenHash, Long userId, String deviceName, Instant expiresAt) {
        this.sessionId = sessionId;
        this.tokenHash = tokenHash;
        this.userId = userId;
        this.deviceName = deviceName;
        this.expiresAt = expiresAt;
    }

    public void rotate(String tokenHash, Instant expiresAt) {
        this.tokenHash = tokenHash;
        this.expiresAt = expiresAt;
    }
}
