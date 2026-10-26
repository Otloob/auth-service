package org.spring.authservice.controller;

import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.spring.authservice.config.JwtConfig.TokenLifetimes;
import org.spring.authservice.dto.LoginRequest;
import org.spring.authservice.dto.LoginResponse;
import org.spring.authservice.dto.RefreshResponse;
import org.spring.authservice.dto.RegisterRequest;
import org.spring.authservice.dto.RegisterResponse;
import org.spring.authservice.exception.AuthException;
import org.spring.authservice.service.AuthService;
import org.spring.authservice.service.DeviceNameResolver;
import org.spring.authservice.service.IssuedTokens;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Validated
@RequestMapping("/auth")
public class AuthController {
    private static final String REFRESH_COOKIE = "refreshToken";

    private final AuthService auth;
    private final TokenLifetimes tokenLifetimes;
    private final boolean secureCookies;

    public AuthController(AuthService auth, TokenLifetimes tokenLifetimes,
                          @Value("${auth.cookie.secure:false}") boolean secureCookies) {
        this.auth = auth;
        this.tokenLifetimes = tokenLifetimes;
        this.secureCookies = secureCookies;
    }

    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    public RegisterResponse register(@Valid @RequestBody RegisterRequest request,
                                     HttpServletRequest servletRequest, HttpServletResponse response) {
        String deviceName = DeviceNameResolver.resolve(servletRequest.getHeader(HttpHeaders.USER_AGENT));
        IssuedTokens tokens = auth.register(request.email(), request.password(), deviceName);
        addRefreshCookie(tokens.refreshToken(), response);
        return new RegisterResponse(tokens.userId(), tokens.email(), tokens.accessToken(),
                tokens.tokenType(), tokens.expiresIn(), tokens.sessionId());
    }

    @PostMapping("/login")
    @ResponseStatus(HttpStatus.OK)
    public LoginResponse login(@Valid @RequestBody LoginRequest request,
                               HttpServletRequest servletRequest,
                               @CookieValue(name = REFRESH_COOKIE, required = false) String existingRefreshToken,
                               HttpServletResponse response) {
        String deviceName = DeviceNameResolver.resolve(servletRequest.getHeader(HttpHeaders.USER_AGENT));
        IssuedTokens tokens = auth.login(request.email(), request.password(), deviceName, existingRefreshToken);
        addRefreshCookie(tokens.refreshToken(), response);
        return new LoginResponse(tokens.accessToken(), tokens.tokenType(), tokens.expiresIn(), tokens.sessionId());
    }

    @PostMapping("/refresh")
    @ResponseStatus(HttpStatus.OK)
    public RefreshResponse refresh(@CookieValue(name = REFRESH_COOKIE, required = false) String refreshToken,
                                   HttpServletResponse response) {
        if (refreshToken == null || refreshToken.isBlank()) {
            throw new AuthException("Refresh token cookie is required");
        }
        IssuedTokens tokens = auth.refresh(refreshToken);
        addRefreshCookie(tokens.refreshToken(), response);
        return new RefreshResponse(tokens.accessToken(), tokens.tokenType(), tokens.expiresIn(), tokens.sessionId());
    }

    @PostMapping("/logout")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void logout(@CookieValue(name = REFRESH_COOKIE, required = false) String refreshToken,
                       HttpServletResponse response) {
        if (refreshToken != null && !refreshToken.isBlank()) auth.logout(refreshToken);
        response.addHeader(HttpHeaders.SET_COOKIE, expiredRefreshCookie().toString());
    }

    private void addRefreshCookie(String refreshToken, HttpServletResponse response) {
        ResponseCookie cookie = ResponseCookie.from(REFRESH_COOKIE, refreshToken)
                .httpOnly(true)
                .secure(secureCookies)
                .sameSite("Strict")
                .path("/auth")
                .maxAge(tokenLifetimes.refresh())
                .build();
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }

    private ResponseCookie expiredRefreshCookie() {
        return ResponseCookie.from(REFRESH_COOKIE, "")
                .httpOnly(true)
                .secure(secureCookies)
                .sameSite("Strict")
                .path("/auth")
                .maxAge(0)
                .build();
    }
}
