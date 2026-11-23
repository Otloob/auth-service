package org.spring.authservice.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.context.annotation.Lazy;
import org.spring.authservice.service.GoogleLoginSuccessHandler;

@Configuration
public class SecurityConfig {
    private final GoogleLoginSuccessHandler googleLoginSuccessHandler;

    public SecurityConfig(@Lazy GoogleLoginSuccessHandler googleLoginSuccessHandler) {
        this.googleLoginSuccessHandler = googleLoginSuccessHandler;
    }

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http.csrf(csrf -> csrf.disable())
                .sessionManagement(
                        session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(HttpMethod.POST, "/auth/register", "/auth/login", "/auth/refresh", "/auth/logout")
                        .permitAll()
                        .requestMatchers("/oauth2/**", "/login/oauth2/**")
                        .permitAll()
                        .anyRequest()
                        .access((authentication, context) -> {
                            Object principal = authentication.get().getPrincipal();
                            return new org.springframework.security.authorization.AuthorizationDecision(
                                    principal instanceof org.springframework.security.oauth2.jwt.Jwt jwt
                                            && "access".equals(jwt.getClaimAsString("token_use")));
                        }))
                .oauth2Login(oauth -> oauth.successHandler(googleLoginSuccessHandler))
                .oauth2ResourceServer(oauth -> oauth.jwt(Customizer.withDefaults()))
                .build();
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
