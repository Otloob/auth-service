package org.spring.authservice.auth;

import java.time.Instant;
import java.util.UUID;
import org.spring.authservice.config.JwtConfig.TokenLifetimes;
import org.spring.authservice.token.RefreshToken;
import org.spring.authservice.token.RefreshTokenRepository;
import org.spring.authservice.user.UserAccount;
import org.spring.authservice.user.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

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

    public UserAccount register(String email, String password) {
        String normalized = normalizeEmail(email);
        validatePassword(password);
        if (users.existsByEmail(normalized)) throw new AuthException("Email is already registered");
        return users.save(new UserAccount(normalized, passwords.encode(password)));
    }

    public TokenResponse login(String email, String password) {
        String normalized = normalizeEmail(email);
        UserAccount user = users.findByEmail(normalized)
                .filter(account -> passwords.matches(password, account.getPasswordHash()))
                .orElseThrow(() -> new AuthException("Invalid email or password"));
        return issueTokens(user);
    }

    @Transactional
    public TokenResponse refresh(String refreshToken) {
        var claims = decoder.decode(refreshToken);
        if (!"refresh".equals(claims.getClaimAsString("token_use"))) throw new AuthException("Invalid refresh token");
        String tokenId = claims.getId();
        RefreshToken stored = refreshTokens.findById(tokenId).orElseThrow(() -> new AuthException("Refresh token is no longer valid"));
        if (stored.isRevoked() || stored.getExpiresAt().isBefore(Instant.now())) throw new AuthException("Refresh token is no longer valid");
        stored.revoke();
        UserAccount user = users.findById(stored.getUserId()).orElseThrow(() -> new AuthException("User no longer exists"));
        return issueTokens(user);
    }

    @Transactional
    public void logout(String refreshToken) {
        var claims = decoder.decode(refreshToken);
        if (!"refresh".equals(claims.getClaimAsString("token_use"))) throw new AuthException("Invalid refresh token");
        refreshTokens.findById(claims.getId()).ifPresent(RefreshToken::revoke);
    }

    private TokenResponse issueTokens(UserAccount user) {
        Instant now = Instant.now();
        String access = encode(user, "access", UUID.randomUUID().toString(), now, now.plus(lifetimes.access()));
        String refreshId = UUID.randomUUID().toString();
        Instant refreshExpiry = now.plus(lifetimes.refresh());
        String refresh = encode(user, "refresh", refreshId, now, refreshExpiry);
        refreshTokens.save(new RefreshToken(refreshId, user.getId(), refreshExpiry));
        return new TokenResponse(access, refresh, "Bearer", lifetimes.access().toSeconds());
    }

    private String encode(UserAccount user, String use, String id, Instant issuedAt, Instant expiresAt) {
        var claims = JwtClaimsSet.builder().issuer(issuer).subject(user.getId().toString()).issuedAt(issuedAt)
                .expiresAt(expiresAt).id(id).claim("email", user.getEmail()).claim("token_use", use).build();
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
}
