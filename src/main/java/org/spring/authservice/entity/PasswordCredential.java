package org.spring.authservice.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "password_credentials")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class PasswordCredential {
    @Id
    @Column(name = "user_id")
    private Long userId;

    @Column(name = "password_hash", nullable = false)
    private String passwordHash;

    public PasswordCredential(Long userId, String passwordHash) {
        this.userId = userId;
        this.passwordHash = passwordHash;
    }
}
