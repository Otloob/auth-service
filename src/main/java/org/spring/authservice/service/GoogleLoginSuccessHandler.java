package org.spring.authservice.service;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.spring.authservice.config.JwtConfig.TokenLifetimes;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.util.Map;

@Component
public class GoogleLoginSuccessHandler implements AuthenticationSuccessHandler {
    private final AuthService auth;
    private final TokenLifetimes lifetimes;
    private final ObjectMapper objectMapper;
    private final boolean secureCookies;

    public GoogleLoginSuccessHandler(AuthService auth, TokenLifetimes lifetimes, ObjectMapper objectMapper,
                                     @Value("${auth.cookie.secure:false}") boolean secureCookies) {
        this.auth = auth;
        this.lifetimes = lifetimes;
        this.objectMapper = objectMapper;
        this.secureCookies = secureCookies;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        OAuth2User googleUser = (OAuth2User) authentication.getPrincipal();
        Object verified = googleUser.getAttribute("email_verified");
        String email = googleUser.getAttribute("email");
        String googleSubject = googleUser.getAttribute("sub");
        if (!Boolean.TRUE.equals(verified) || email == null || email.isBlank()
                || googleSubject == null || googleSubject.isBlank()) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Google account must have a verified email");
            return;
        }

        IssuedTokens tokens = auth
                .loginWithGoogle(email, googleSubject,
                        DeviceNameResolver.resolve(request.getHeader(HttpHeaders.USER_AGENT)));

        ResponseCookie cookie = ResponseCookie
                .from("refreshToken", tokens.refreshToken())
                .httpOnly(true)
                .secure(secureCookies)
                .sameSite("Strict")
                .path("/auth")
                .maxAge(lifetimes.refresh())
                .build();

        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        // this is JSON response after success login, to be changed to redirect to a front page
        objectMapper
                .writeValue(response.getOutputStream(), Map.of(
                        "userId", tokens.userId(), "email", tokens.email(), "accessToken", tokens.accessToken(),
                        "tokenType", tokens.tokenType(), "expiresIn", tokens.expiresIn(), "sessionId", tokens.sessionId()));
    }
}
