package org.spring.authservice.repository;

import java.time.Instant;
import java.util.Optional;
import org.spring.authservice.entity.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import jakarta.persistence.LockModeType;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, String> {
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select rt from RefreshToken rt where rt.sessionId = :sessionId")
    Optional<RefreshToken> findBySessionIdForUpdate(@Param("sessionId") String sessionId);

    long deleteAllByExpiresAtBefore(Instant now);
}
