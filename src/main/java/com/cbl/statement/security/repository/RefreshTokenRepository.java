package com.cbl.statement.security.repository;

import com.cbl.statement.security.entity.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    Optional<RefreshToken> findByRefreshToken(String refreshToken);

    @Query(value = "SELECT rt.* FROM refresh_token rt " +
                           "INNER JOIN user_info ui ON rt.UserId = ui.Id " +
                           "WHERE ui.Email = :userEmail and rt.Revoked = false ", nativeQuery = true)
    Optional<List<RefreshToken>> findAllRefreshTokenByUserEmail(String userEmail);
}
