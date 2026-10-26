package org.spring.authservice.dto;

public record RegisterResponse(
        Long userId,
        String email,
        String accessToken,
        String tokenType,
        long expiresIn,
        String sessionId) {
}
