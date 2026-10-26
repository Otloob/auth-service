package org.spring.authservice.service;

/** Internal token bundle. The refresh token is only sent as an HttpOnly cookie. */
public record IssuedTokens(
        String accessToken,
        String refreshToken,
        String tokenType,
        long expiresIn,
        String sessionId,
        Long userId,
        String email) {}
