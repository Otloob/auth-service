package org.spring.authservice.service;

import java.time.Instant;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.UUID;
import org.spring.authservice.config.JwtConfig.TokenLifetimes;
import org.spring.authservice.entity.RefreshToken;
import org.spring.authservice.entity.UserAccount;
import org.spring.authservice.exception.AuthException;
import org.spring.authservice.repository.RefreshTokenRepository;
import org.spring.authservice.repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.jwt.JwtException;

@Service
public class AuthService {
    private final UserRepository users;
    private final RefreshTokenRepository refreshTokens;
    private final PasswordEncoder passwords;
    private final JwtEncoder encoder;
    private final org.springframework.security.oauth2.jwt.JwtDecoder decoder;
    private final TokenLifetimes lifetimes;
    private final String issuer;

    public AuthService(UserRepository users, RefreshTokenRepository refreshTokens, PasswordEncoder passwords,
                       JwtEncoder encoder, org.springframework.security.oauth2.jwt.JwtDecoder decoder,
                       TokenLifetimes lifetimes, @Value("${auth.jwt.issuer}") String issuer) {
        this.users = users; this.refreshTokens = refreshTokens; this.passwords = passwords;
        this.encoder = encoder; this.decoder = decoder; this.lifetimes = lifetimes; this.issuer = issuer;
    }

    @Transactional
    public IssuedTokens register(String email, String password, String deviceName) {
        String normalized = normalizeEmail(email);
        validatePassword(password);
        if (users.existsByEmail(normalized)) throw new AuthException("Email is already registered", HttpStatus.CONFLICT);
        UserAccount user = users.save(new UserAccount(normalized, passwords.encode(password)));
        return issueTokens(user, normalizeDeviceName(deviceName), UUID.randomUUID().toString());
    }

    @Transactional
    public IssuedTokens login(String email, String password, String deviceName, String existingRefreshToken) {
        String normalized = normalizeEmail(email);
        UserAccount user = users.findByEmail(normalized)
                .filter(account -> account.getPasswordHash() != null
                        && passwords.matches(password, account.getPasswordHash()))
                .orElseThrow(() -> new AuthException("Invalid email or password"));

        SessionDetails existingSession = findSessionToReuse(existingRefreshToken, user);
        if (existingSession != null) {
            return issueTokens(user, existingSession.deviceName(), existingSession.sessionId());
        }
        return issueTokens(user, normalizeDeviceName(deviceName), UUID.randomUUID().toString());
    }

    @Transactional
    public IssuedTokens loginWithGoogle(String email, String deviceName) {
        String normalized = normalizeEmail(email);
        UserAccount user = users.findByEmail(normalized)
                .orElseGet(() -> users.save(new UserAccount(normalized, null)));
        return issueTokens(user, normalizeDeviceName(deviceName), UUID.randomUUID().toString());
    }

    @Transactional
    public RefreshResult refresh(String refreshToken) {
        var claims = decoder.decode(refreshToken);
        if (!"refresh".equals(claims.getClaimAsString("token_use"))) throw new AuthException("Invalid refresh token");
        String tokenId = claims.getId();
        RefreshToken stored = refreshTokens.findByTokenIdForUpdate(tokenId)
                .orElseThrow(() -> new AuthException("Refresh token is no longer valid"));
        String sessionId = stored.getSessionId();
        if (sessionId == null || !sessionId.equals(claims.getClaimAsString("session_id"))
                || !stored.getUserId().toString().equals(claims.getSubject())) {
            throw new AuthException("Refresh token is no longer valid");
        }
        if (stored.getExpiresAt().isBefore(Instant.now())) throw new AuthException("Refresh token is no longer valid");

        String presentedHash = hashRefreshToken(refreshToken);
        if (stored.getTokenHash() != null && !MessageDigest.isEqual(
                stored.getTokenHash().getBytes(StandardCharsets.US_ASCII), presentedHash.getBytes(StandardCharsets.US_ASCII))) {
            revokeSession(sessionId);
            return new RefreshResult(null, true);
        }
        if (stored.isRevoked()) {
            revokeSession(sessionId);
            return new RefreshResult(null, true);
        }

        // Rows created before V5 have no hash; their signed JWT and persisted token ID still identify them.
        stored.setTokenHash(presentedHash);
        stored.revoke();
        UserAccount user = users.findById(stored.getUserId()).orElseThrow(() -> new AuthException("User no longer exists"));
        IssuedTokens issued = issueTokens(user, normalizeDeviceName(stored.getDeviceName()), sessionId);
        return new RefreshResult(issued, false);
    }

    @Transactional
    public void logout(String refreshToken) {
        var claims = decoder.decode(refreshToken);
        if (!"refresh".equals(claims.getClaimAsString("token_use"))) throw new AuthException("Invalid refresh token");
        String sessionId = claims.getClaimAsString("session_id");
        if (sessionId == null) refreshTokens.findById(claims.getId()).ifPresent(refreshTokens::delete);
        else refreshTokens.deleteAll(refreshTokens.findAllBySessionId(sessionId));
    }

    private IssuedTokens issueTokens(UserAccount user, String deviceName, String sessionId) {
        Instant now = Instant.now();
        refreshTokens.deleteAllByExpiresAtBefore(now);
        String access = encode(user, "access", UUID.randomUUID().toString(), sessionId, now, now.plus(lifetimes.access()));
        String refreshId = UUID.randomUUID().toString();
        Instant refreshExpiry = now.plus(lifetimes.refresh());
        String refresh = encode(user, "refresh", refreshId, sessionId, now, refreshExpiry);
        refreshTokens.save(new RefreshToken(refreshId, hashRefreshToken(refresh), user.getId(), sessionId, deviceName, refreshExpiry));
        return new IssuedTokens(access, refresh, "Bearer", lifetimes.access().toSeconds(), sessionId,
                user.getId(), user.getEmail());
    }

    private void revokeSession(String sessionId) {
        for (RefreshToken token : refreshTokens.findAllBySessionIdForUpdate(sessionId)) token.revoke();
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

        RefreshToken stored = refreshTokens.findById(claims.getId()).orElse(null);
        if (stored == null) return null;
        if (stored.getExpiresAt().isBefore(Instant.now())) {
            refreshTokens.delete(stored);
            return null;
        }
        if (stored.isRevoked()) {
            if (stored.getSessionId() != null) revokeSession(stored.getSessionId());
            return null;
        }

        String sessionId = stored.getSessionId();
        String claimSessionId = claims.getClaimAsString("session_id");
        if (!authenticatedUser.getId().equals(stored.getUserId())
                || !authenticatedUser.getId().toString().equals(claims.getSubject())
                || (claimSessionId != null && !claimSessionId.equals(sessionId))) {
            if (sessionId == null) refreshTokens.delete(stored);
            else refreshTokens.deleteAll(refreshTokens.findAllBySessionId(sessionId));
            return null;
        }

        if (sessionId == null) {
            refreshTokens.delete(stored);
            sessionId = UUID.randomUUID().toString();
        } else {
            refreshTokens.deleteAll(refreshTokens.findAllBySessionId(sessionId));
        }
        return new SessionDetails(sessionId, normalizeDeviceName(stored.getDeviceName()));
    }

    private String encode(UserAccount user, String use, String id, String sessionId, Instant issuedAt, Instant expiresAt) {
        var claims = JwtClaimsSet.builder().issuer(issuer).subject(user.getId().toString()).issuedAt(issuedAt)
                .expiresAt(expiresAt).id(id).claim("email", user.getEmail()).claim("token_use", use)
                .claim("session_id", sessionId).build();
        return encoder.encode(JwtEncoderParameters.from(
                org.springframework.security.oauth2.jwt.JwsHeader.with(MacAlgorithm.HS256).build(), claims)).getTokenValue();
    }

    private static String normalizeEmail(String email) {
        if (email == null || !email.matches("^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$")) throw new AuthException("A valid email is required");
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

    private record SessionDetails(String sessionId, String deviceName) {}
    public record RefreshResult(IssuedTokens tokens, boolean reuseDetected) {}
}
