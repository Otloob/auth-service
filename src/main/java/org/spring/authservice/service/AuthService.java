package org.spring.authservice.service;

import org.spring.authservice.config.JwtConfig.TokenLifetimes;
import org.spring.authservice.entity.PasswordCredential;
import org.spring.authservice.entity.RefreshToken;
import org.spring.authservice.entity.OAuthIdentity;
import org.spring.authservice.entity.UserAccount;
import org.spring.authservice.exception.AuthException;
import org.spring.authservice.repository.OAuthIdentityRepository;
import org.spring.authservice.repository.PasswordCredentialRepository;
import org.spring.authservice.repository.RefreshTokenRepository;
import org.spring.authservice.repository.UserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.UUID;

@Service
public class AuthService {
    private final UserRepository users;
    private final PasswordCredentialRepository passwordCredentials;
    private final OAuthIdentityRepository oauthIdentities;
    private final RefreshTokenRepository refreshTokens;
    private final PasswordEncoder passwords;
    private final JwtEncoder encoder;
    private final org.springframework.security.oauth2.jwt.JwtDecoder decoder;
    private final TokenLifetimes lifetimes;
    private final String issuer;

    public AuthService(UserRepository users, PasswordCredentialRepository passwordCredentials,
                       OAuthIdentityRepository oauthIdentities, RefreshTokenRepository refreshTokens, PasswordEncoder passwords,
                       JwtEncoder encoder, org.springframework.security.oauth2.jwt.JwtDecoder decoder,
                       TokenLifetimes lifetimes, @Value("${auth.jwt.issuer}") String issuer) {
        this.users = users;
        this.passwordCredentials = passwordCredentials;
        this.oauthIdentities = oauthIdentities;
        this.refreshTokens = refreshTokens;
        this.passwords = passwords;
        this.encoder = encoder;
        this.decoder = decoder;
        this.lifetimes = lifetimes;
        this.issuer = issuer;
    }

    @Transactional
    public IssuedTokens register(String email, String password, String deviceName) {
        String normalized = normalizeEmail(email);
        validatePassword(password);
        if (users.existsByEmail(normalized))
            throw new AuthException("Email is already registered", HttpStatus.CONFLICT);
        UserAccount user = users.save(new UserAccount(normalized));
        passwordCredentials.save(new PasswordCredential(user.getId(), passwords.encode(password)));
        return issueTokens(user, normalizeDeviceName(deviceName), UUID.randomUUID().toString(), null);
    }

    @Transactional
    public IssuedTokens login(String email, String password, String deviceName, String existingRefreshToken) {
        String normalized = normalizeEmail(email);
        UserAccount user = users.findByEmail(normalized)
                .orElseThrow(() -> new AuthException("Invalid email or password"));
        if (passwordCredentials.findById(user.getId())
                .filter(account -> passwords.matches(password, account.getPasswordHash()))
                .isEmpty()) {
            throw new AuthException("Invalid email or password");
        }

        SessionDetails existingSession = findSessionToReuse(existingRefreshToken, user);
        if (existingSession != null) {
            return issueTokens(user, existingSession.deviceName(), existingSession.session().getSessionId(),
                    existingSession.session());
        }
        return issueTokens(user, normalizeDeviceName(deviceName), UUID.randomUUID().toString(), null);
    }

    @Transactional
    public IssuedTokens loginWithGoogle(String email, String googleSubject, String deviceName) {
        String normalized = normalizeEmail(email);
        OAuthIdentity identity = oauthIdentities.findByProviderAndProviderSubject("google", googleSubject)
                .orElse(null);
        UserAccount user;
        if (identity != null) {
            user = users.findById(identity.getUserId())
                    .orElseThrow(() -> new AuthException("Linked user no longer exists"));
        } else {
            // Google has already confirmed this email, so reuse an account with the same verified address.
            user = users.findByEmail(normalized).orElseGet(() -> users.save(new UserAccount(normalized)));
            oauthIdentities.save(new OAuthIdentity(user.getId(), "google", googleSubject, normalized));
        }
        return issueTokens(user, normalizeDeviceName(deviceName), UUID.randomUUID().toString(), null);
    }

    @Transactional
    public RefreshResult refresh(String refreshToken) {
        var claims = decoder.decode(refreshToken);
        if (!"refresh".equals(claims.getClaimAsString("token_use"))) throw new AuthException("Invalid refresh token");
        String sessionId = claims.getClaimAsString("session_id");
        if (sessionId == null || sessionId.isBlank()) throw new AuthException("Refresh token is no longer valid");
        RefreshToken stored = refreshTokens.findBySessionIdForUpdate(sessionId)
                .orElseThrow(() -> new AuthException("Refresh token is no longer valid"));
        if (!stored.getUserId().toString().equals(claims.getSubject())) {
            throw new AuthException("Refresh token is no longer valid");
        }
        if (stored.getExpiresAt().isBefore(Instant.now())) throw new AuthException("Refresh token is no longer valid");

        String presentedHash = hashRefreshToken(refreshToken);
        if (!hashMatches(stored.getTokenHash(), presentedHash)) {
            refreshTokens.delete(stored);
            return new RefreshResult(null, true);
        }

        UserAccount user = users.findById(stored.getUserId()).orElseThrow(() -> new AuthException("User no longer exists"));
        IssuedTokens issued = issueTokens(user, normalizeDeviceName(stored.getDeviceName()), sessionId, stored);
        return new RefreshResult(issued, false);
    }

    @Transactional
    public void logout(String refreshToken) {
        var claims = decoder.decode(refreshToken);
        if (!"refresh".equals(claims.getClaimAsString("token_use")))
            throw new AuthException("Invalid refresh token");
        String sessionId = claims.getClaimAsString("session_id");
        if (sessionId != null) {
            refreshTokens.findBySessionIdForUpdate(sessionId)
                    .filter(session -> session.getUserId().toString().equals(claims.getSubject()))
                    .ifPresent(refreshTokens::delete);
        }
    }

    private IssuedTokens issueTokens(UserAccount user, String deviceName, String sessionId, RefreshToken session) {
        Instant now = Instant.now();
        refreshTokens.deleteAllByExpiresAtBefore(now);

        String access = encode(user, "access", UUID.randomUUID().toString(), sessionId, now, now.plus(lifetimes.access()));
        Instant refreshExpiry = now.plus(lifetimes.refresh());
        String refresh = encode(user, "refresh", UUID.randomUUID().toString(), sessionId, now, refreshExpiry);
        String refreshHash = hashRefreshToken(refresh);
        if (session == null) {
            refreshTokens.save(new RefreshToken(sessionId, refreshHash, user.getId(), deviceName, refreshExpiry));
        } else {
            session.rotate(refreshHash, refreshExpiry);
        }
        return new IssuedTokens(access, refresh, "Bearer", lifetimes.access().toSeconds(), sessionId,
                user.getId(), user.getEmail());
    }

    private static boolean hashMatches(String storedHash, String presentedHash) {
        return MessageDigest.isEqual(storedHash.getBytes(StandardCharsets.US_ASCII),
                presentedHash.getBytes(StandardCharsets.US_ASCII));
    }

    private static String hashRefreshToken(String token) {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(token.getBytes(StandardCharsets.UTF_8));
            return java.util.HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
    }

    private SessionDetails findSessionToReuse(String refreshToken, UserAccount authenticatedUser) {
        if (refreshToken == null || refreshToken.isBlank()) return null;

        final org.springframework.security.oauth2.jwt.Jwt claims;
        try {
            claims = decoder.decode(refreshToken);
        } catch (JwtException exception) {
            return null;
        }
        if (!"refresh".equals(claims.getClaimAsString("token_use"))) return null;

        String sessionId = claims.getClaimAsString("session_id");
        if (sessionId == null) return null;
        RefreshToken stored = refreshTokens.findBySessionIdForUpdate(sessionId).orElse(null);
        if (stored == null) return null;
        if (stored.getExpiresAt().isBefore(Instant.now())) {
            refreshTokens.delete(stored);
            return null;
        }
        if (!authenticatedUser.getId().equals(stored.getUserId())
                || !authenticatedUser.getId().toString().equals(claims.getSubject())
                || !sessionId.equals(stored.getSessionId())) {
            return null;
        }
        if (!hashMatches(stored.getTokenHash(), hashRefreshToken(refreshToken))) {
            refreshTokens.delete(stored);
            return null;
        }
        return new SessionDetails(stored);
    }

    private String encode(UserAccount user, String use, String id, String sessionId, Instant issuedAt, Instant expiresAt) {
        var claims = JwtClaimsSet.builder().issuer(issuer).subject(user.getId().toString()).issuedAt(issuedAt)
                .expiresAt(expiresAt).id(id).claim("email", user.getEmail()).claim("token_use", use)
                .claim("session_id", sessionId).build();
        return encoder.encode(JwtEncoderParameters.from(
                org.springframework.security.oauth2.jwt.JwsHeader.with(MacAlgorithm.HS256).build(), claims)).getTokenValue();
    }

    private static String normalizeEmail(String email) {
        if (email == null || !email.matches("^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$"))
            throw new AuthException("A valid email is required");
        return email.trim().toLowerCase(java.util.Locale.ROOT);
    }

    private static void validatePassword(String password) {
        if (password == null || password.length() < 12 || password.length() > 72)
            throw new AuthException("Password must be between 12 and 72 characters");
    }

    private static String normalizeDeviceName(String deviceName) {
        if (deviceName == null || deviceName.isBlank()) return "Unknown device";
        return deviceName.trim();
    }

    private record SessionDetails(RefreshToken session) {
        private String deviceName() { return normalizeDeviceName(session.getDeviceName()); }
    }

    public record RefreshResult(IssuedTokens tokens, boolean reuseDetected) {
    }
}
