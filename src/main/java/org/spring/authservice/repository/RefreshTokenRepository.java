package org.spring.authservice.repository;

import org.spring.authservice.entity.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import jakarta.persistence.LockModeType;
import java.time.Instant;
import java.util.List;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, String> {
    List<RefreshToken> findAllBySessionId(String sessionId);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select token from RefreshToken token where token.tokenId = :tokenId")
    java.util.Optional<RefreshToken> findByTokenIdForUpdate(@Param("tokenId") String tokenId);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select token from RefreshToken token where token.sessionId = :sessionId")
    List<RefreshToken> findAllBySessionIdForUpdate(@Param("sessionId") String sessionId);

    long deleteAllByExpiresAtBefore(Instant now);
}
