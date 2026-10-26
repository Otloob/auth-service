package org.spring.authservice.dto;

public record LoginResponse(String accessToken, String tokenType, long expiresIn, String sessionId) {}
