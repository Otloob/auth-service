package org.spring.authservice.auth;

public record TokenResponse(String accessToken, String refreshToken, String tokenType, long expiresIn) {}
