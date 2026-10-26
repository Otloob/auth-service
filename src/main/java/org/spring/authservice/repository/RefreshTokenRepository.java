package org.spring.authservice.repository;

import org.spring.authservice.entity.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, String> {
    List<RefreshToken> findAllBySessionId(String sessionId);
}
