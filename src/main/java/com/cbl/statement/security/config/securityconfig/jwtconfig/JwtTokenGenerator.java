package com.cbl.statement.security.config.securityconfig.jwtconfig;

import com.cbl.statement.security.config.appconfig.AppConfig;
import com.cbl.statement.security.repository.PrivilegeRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collection;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class JwtTokenGenerator {

    private final JwtEncoder jwtEncoder;
    private final AppConfig appConfig;
    private final PrivilegeRepository privilegeRepository;

    public String generateAccessToken(Authentication authentication) {

        log.info("[JwtTokenGenerator:generateAccessToken] Token Creation Started for:{}", authentication.getName());

        final String roles = getRolesOfUser(authentication);

        final String permissions = getPermissionsFromRoles(roles);

        final JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("cbl_statement")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plus(Long.parseLong(appConfig.getAccessTokenExpiry()), ChronoUnit.MINUTES))
                .subject(authentication.getName())
                .claim("scope", permissions)
                .build();

        return jwtEncoder.encode(JwtEncoderParameters.from(getJwsHeader(), claims)).getTokenValue();
    }

    public String generateRefreshToken(Authentication authentication) {

        log.info("[JwtTokenGenerator:generateRefreshToken] Token Creation Started for:{}", authentication.getName());

        final JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("cbl_statement")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plus(Long.parseLong(appConfig.getRefreshTokenExpiry()), ChronoUnit.DAYS))
                .subject(authentication.getName())
                .claim("scope", "REFRESH_TOKEN")
                .build();

        return jwtEncoder.encode(JwtEncoderParameters.from(getJwsHeader(), claims)).getTokenValue();
    }

    private static JwsHeader getJwsHeader() {
        return JwsHeader.with(() -> "HS256")
                .type("JWT")
                .header("issuer", "cbl")
                .header("token-version", "v1.0")
                .build();
    }

    private static String getRolesOfUser(Authentication authentication) {
        return authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(" "));
    }

    private String getPermissionsFromRoles(String roles) {

        final Collection<String> privileges = privilegeRepository.findPrivilegesByRoleName(roles)
                                                        .orElseThrow(() -> new RuntimeException(String.format("No privileges found by role: %s", roles)));

        return String.join(" ", privileges);
    }
}
