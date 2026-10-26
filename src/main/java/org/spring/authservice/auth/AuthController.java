package org.spring.authservice.auth;

import java.util.Map;
import org.spring.authservice.user.UserAccount;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class AuthController {
    private final AuthService auth;
    public AuthController(AuthService auth) { this.auth = auth; }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody Credentials request) {
        UserAccount user = auth.register(request.email(), request.password());
        return ResponseEntity.status(HttpStatus.CREATED).body(Map.of("id", user.getId(), "email", user.getEmail()));
    }

    @PostMapping("/login")
    public TokenResponse login(@RequestBody Credentials request) { return auth.login(request.email(), request.password()); }

    @PostMapping("/refresh")
    public TokenResponse refresh(@RequestBody RefreshRequest request) { return auth.refresh(request.refreshToken()); }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@RequestBody RefreshRequest request) {
        auth.logout(request.refreshToken());
        return ResponseEntity.noContent().build();
    }

    @ExceptionHandler(AuthException.class)
    public ResponseEntity<Map<String, String>> handleAuthError(AuthException exception) {
        HttpStatus status = exception.getMessage().contains("already registered") ? HttpStatus.CONFLICT : HttpStatus.UNAUTHORIZED;
        if (exception.getMessage().contains("required") || exception.getMessage().contains("between")) status = HttpStatus.BAD_REQUEST;
        return ResponseEntity.status(status).body(Map.of("error", exception.getMessage()));
    }

    public record Credentials(String email, String password) {}
    public record RefreshRequest(String refreshToken) {}
}
