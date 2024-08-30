package com.cbl.statement.security.service;

import com.cbl.statement.security.config.appconfig.AppConfig;
import com.cbl.statement.security.config.securityconfig.jwtconfig.JwtTokenUtils;
import com.cbl.statement.security.consts.ExceptionMsg;
import com.cbl.statement.security.consts.ResponseMsg;
import com.cbl.statement.security.exc.TokenNotFoundException;
import com.cbl.statement.security.repository.RefreshTokenRepository;
import com.cbl.statement.security.response.ResponseHandler;
import io.jsonwebtoken.io.Decoders;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.ArrayList;
import java.util.Map;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class LogoutHandlerService implements LogoutHandler {
    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtTokenUtils jwtTokenUtils;
    private final AppConfig appConfig;


    @SneakyThrows
    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {

        final var errors = new ArrayList<Map<String, String>>();
        try {
            final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

            if (!authHeader.startsWith(OAuth2AccessToken.TokenType.BEARER.getValue())) {
                return;
            }

            final String refreshToken = authHeader.substring(7);
            final Jwt decodedRefreshToken = jwtDecoder().decode(refreshToken);
            final var userEmail = jwtTokenUtils.getUserName(decodedRefreshToken);

            revokeRefreshToken(refreshToken);
            //revokeAllRefreshTokenForUser(userEmail);
            ResponseHandler.sendResponse(true
                                        , HttpStatus.OK
                                        , ResponseMsg.SUCCESSFUL_LOGOUT
                                        , response
                                        , Optional.empty()
                                        , errors);
        } catch (RuntimeException e) {
            errors.add(Map.of("message", e.getMessage()));
            ResponseHandler.sendResponse(false
                                        , HttpStatus.NOT_FOUND
                                        , ""
                                        , response
                                        , Optional.empty()
                                        , errors);
        }
    }

    private void revokeRefreshToken(String refreshToken) {
        refreshTokenRepository.findByRefreshToken(refreshToken)
                              .map(refreshTokenEntity -> {
                    if (refreshTokenEntity.isRevoked()) {
                        throw new IllegalStateException(ExceptionMsg.REFRESH_TOKEN_ALREADY_REVOKED);
                    }
                    refreshTokenEntity.setRevoked(true);
                    return refreshTokenRepository.save(refreshTokenEntity);
                })
                              .orElseThrow(() -> new TokenNotFoundException(ExceptionMsg.REFRESH_TOKEN_NOT_FOUND_DURING_LOGOUT));
    }

    private void revokeAllRefreshTokenForUser(String userEmail) {
        refreshTokenRepository.findAllRefreshTokenByUserEmail(userEmail)
                              .ifPresent(refreshTokenEntities -> {
                    refreshTokenEntities.forEach(refreshTokenEntity -> refreshTokenEntity.setRevoked(true));
                    refreshTokenRepository.saveAll(refreshTokenEntities);
                });
    }

    private JwtDecoder jwtDecoder() {
        final byte[] secretByte = Decoders.BASE64.decode(appConfig.getJwtSecret());
        final SecretKey secretKey = new SecretKeySpec(secretByte, 0, secretByte.length, MacAlgorithm.HS256.getName());
        return NimbusJwtDecoder.withSecretKey(secretKey).macAlgorithm(MacAlgorithm.HS256).build();
    }
}
