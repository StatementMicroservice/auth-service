package com.cbl.statement.security.config.securityconfig.jwtconfig;

import com.cbl.statement.security.config.appconfig.AppConfig;
import com.cbl.statement.security.config.userconfig.UserInfoConfig;
import com.cbl.statement.security.consts.ExceptionMsg;
import com.cbl.statement.security.repository.UserRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collection;
import java.util.Objects;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtTokenUtils {
    private final UserRepository useruserRepository;
    private final AppConfig appConfig;

    public String getUserName(Jwt jwtToken) {
        return jwtToken.getSubject();
    }

    public boolean isTokenValid(Jwt jwtToken, UserDetails userDetails) {
        final String userName = getUserName(jwtToken);
        final boolean isTokenExpired = isTokenExpired(jwtToken);
        final boolean isTokenUserSameAsDatabase = userName.equals(userDetails.getUsername());
        return !isTokenExpired && isTokenUserSameAsDatabase;
    }

    public boolean isTokenExpired(Jwt jwtToken) {
        return Objects.requireNonNull(jwtToken.getExpiresAt()).isBefore(Instant.now());
    }

    public Claims getClaims(final String token) {
        final Key key = Keys.hmacShaKeyFor(appConfig.getJwtSecret().getBytes());
        return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody();
    }

    public Collection<GrantedAuthority> getAuthoritiesFromJwt(Jwt jwtToken) {
        final var authoritiesClaim = jwtToken.getClaims().get("scope");

        if (authoritiesClaim instanceof String authoritiesString) {
            return Arrays.stream(authoritiesString.split(","))
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toList());
        } else {
            throw new IllegalArgumentException(ExceptionMsg.UNSUPPORTED_AUTHORITIES);
        }
    }

    public UserDetails userDetails(String emailId) {
        return useruserRepository
                .findByEmail(emailId)
                .map(UserInfoConfig::new)
                .orElseThrow(() -> new UsernameNotFoundException(String.format(ExceptionMsg.USER_NOT_FOUND_DURING_TOKEN_VALIDATION, emailId)));
    }

    public UserDetails getUserDetailsWithoutThrowingException(String emailId) {
        return useruserRepository
                       .findByEmail(emailId)
                       .map(UserInfoConfig::new)
                       .orElse(null);
    }
}
