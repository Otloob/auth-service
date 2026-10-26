package org.spring.authservice.dto;

public record RefreshResponse(String accessToken, String tokenType, long expiresIn, String sessionId) {}
