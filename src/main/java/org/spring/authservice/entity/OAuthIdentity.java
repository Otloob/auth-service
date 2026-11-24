package org.spring.authservice.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "oauth_identities", uniqueConstraints = {
        @UniqueConstraint(name = "ux_oauth_provider_subject", columnNames = {"provider", "provider_subject"}),
        @UniqueConstraint(name = "ux_oauth_user_provider", columnNames = {"user_id", "provider"})
})
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class OAuthIdentity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "user_id", nullable = false)
    private Long userId;

    @Column(nullable = false, length = 50)
    private String provider;

    @Column(name = "provider_subject", nullable = false, length = 255)
    private String providerSubject;

    @Column(name = "provider_email", nullable = false, length = 255)
    private String providerEmail;

    public OAuthIdentity(Long userId, String provider, String providerSubject, String providerEmail) {
        this.userId = userId;
        this.provider = provider;
        this.providerSubject = providerSubject;
        this.providerEmail = providerEmail;
    }
}
