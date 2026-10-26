package org.spring.authservice.config;

import java.time.Duration;
import java.util.Base64;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.jwt.BadJwtException;
import com.nimbusds.jose.jwk.source.ImmutableSecret;

@Configuration
public class JwtConfig {
    @Bean
    SecretKey jwtSecretKey(@Value("${auth.jwt.secret}") String encodedSecret) {
        if (encodedSecret == null || encodedSecret.isBlank()) {
            throw new IllegalStateException("JWT_SECRET must be set to a base64-encoded key of at least 32 bytes");
        }
        byte[] key = Base64.getDecoder().decode(encodedSecret);
        if (key.length < 32) throw new IllegalStateException("JWT_SECRET must decode to at least 32 bytes");
        return new SecretKeySpec(key, "HmacSHA256");
    }

    @Bean
    JwtEncoder jwtEncoder(SecretKey key) {
        return new NimbusJwtEncoder(new ImmutableSecret<>(key));
    }

    @Bean
    JwtDecoder jwtDecoder(SecretKey key, @Value("${auth.jwt.issuer}") String issuer) {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withSecretKey(key).macAlgorithm(MacAlgorithm.HS256).build();
        decoder.setJwtValidator(org.springframework.security.oauth2.jwt.JwtValidators.createDefaultWithIssuer(issuer));
        return token -> {
            validateCanonicalEncoding(token);
            return decoder.decode(token);
        };
    }

    private static void validateCanonicalEncoding(String token) {
        String[] segments = token.split("\\.", -1);
        if (segments.length != 3) throw new BadJwtException("JWT must contain three compact segments");

        Base64.Decoder decoder = Base64.getUrlDecoder();
        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        for (String segment : segments) {
            if (segment.isEmpty() || !segment.matches("[A-Za-z0-9_-]+")) {
                throw new BadJwtException("JWT contains an invalid Base64URL segment");
            }
            try {
                if (!encoder.encodeToString(decoder.decode(segment)).equals(segment)) {
                    throw new BadJwtException("JWT uses a non-canonical Base64URL encoding");
                }
            } catch (IllegalArgumentException exception) {
                throw new BadJwtException("JWT contains an invalid Base64URL segment", exception);
            }
        }
    }

    @Bean
    TokenLifetimes tokenLifetimes(@Value("${auth.jwt.access-token-ttl}") Duration access,
                                  @Value("${auth.jwt.refresh-token-ttl}") Duration refresh) {
        if (access.isZero() || access.isNegative() || refresh.isZero() || refresh.isNegative()) {
            throw new IllegalStateException("JWT token lifetimes must be positive");
        }
        return new TokenLifetimes(access, refresh);
    }

    public record TokenLifetimes(Duration access, Duration refresh) {}
}
