package com.cbl.statement.security.config.securityconfig.jwtconfig;

import com.cbl.statement.security.consts.ExceptionMsg;
import com.cbl.statement.security.exc.AuthorizationHeaderNotFoundException;
import com.cbl.statement.security.exc.TokenNotFoundException;
import com.cbl.statement.security.response.ResponseHandler;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.logging.log4j.util.Strings;
import org.jetbrains.annotations.NotNull;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidationException;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Map;
import java.util.Optional;

@RequiredArgsConstructor
@Slf4j
public class JwtAccessTokenFilter extends OncePerRequestFilter {
    private final JwtTokenUtils jwtTokenUtils;
    private final JwtDecoder jwtDecoder;

    @Override
    protected void doFilterInternal(@NotNull HttpServletRequest request, @NotNull HttpServletResponse response, @NotNull FilterChain filterChain) throws ServletException, IOException {
        final var errors = new ArrayList<Map<String, String>>();
        try {
            log.info("[JwtAccessTokenFilter:doFilterInternal] :: Started Filtering the Http Request:{}", request.getRequestURI());
            final String authHeader = Optional.ofNullable(request.getHeader(HttpHeaders.AUTHORIZATION))
                                              .orElseThrow(() -> new TokenNotFoundException(ExceptionMsg.MISSING_BEARER_TOKEN));

            if (!authHeader.startsWith(OAuth2AccessToken.TokenType.BEARER.getValue())) {
                errors.add(Map.of("message", ExceptionMsg.INVALID_BEARER_TOKEN));
                log.info("[JwtAccessTokenFilter:doFilterInternal] Token is invalid.");

                ResponseHandler.sendResponse(false
                                            , HttpStatus.UNAUTHORIZED
                                            , Strings.EMPTY
                                            , response
                                            , Optional.empty()
                                            , errors);
            }

            final String token = authHeader.substring(7);
            final Jwt jwtToken = jwtDecoder.decode(token);
            final String userName = jwtTokenUtils.getUserName(jwtToken);

            if (!userName.isEmpty() && SecurityContextHolder.getContext().getAuthentication() == null) {
                final UserDetails userDetails = jwtTokenUtils.userDetails(userName);

                if (jwtTokenUtils.isTokenValid(jwtToken, userDetails)) {
                    final var securityContext = SecurityContextHolder.createEmptyContext();
                    final var authorities = jwtTokenUtils.getAuthoritiesFromJwt(jwtToken);

                    final var createdToken = new UsernamePasswordAuthenticationToken(
                            userName,
                            null,
                            authorities
                    );
                    createdToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    securityContext.setAuthentication(createdToken);
                    SecurityContextHolder.setContext(securityContext);
                    log.info("[JwtAccessTokenFilter:doFilterInternal] Token is valid, setting security context.");
                } else {
                    errors.add(Map.of("message", ExceptionMsg.TOKEN_EXPIRED));
                    log.info("[JwtAccessTokenFilter:doFilterInternal] Token is expired.");

                    ResponseHandler.sendResponse(false
                                                , HttpStatus.UNAUTHORIZED
                                                , Strings.EMPTY
                                                , response
                                                , Optional.empty()
                                                , errors);
                }
                log.info("[JwtAccessTokenFilter:doFilterInternal] Completed");
                filterChain.doFilter(request, response);
            }
        } catch (BadJwtException | AuthorizationHeaderNotFoundException | TokenNotFoundException e) {
            if (e instanceof JwtValidationException) {
                errors.add(Map.of("message", ExceptionMsg.TOKEN_EXPIRED));
            } else {
                errors.add(Map.of("message", e.getMessage()));
            }
            ResponseHandler.sendResponse(false
                                       , HttpStatus.UNAUTHORIZED
                                       , Strings.EMPTY
                                       , response
                                       , Optional.empty()
                                       , errors);
        } catch (UsernameNotFoundException e) {
            errors.add(Map.of("message", e.getMessage()));

            ResponseHandler.sendResponse(false
                                       , HttpStatus.NOT_FOUND
                                       , Strings.EMPTY
                                       , response
                                       , Optional.empty()
                                       , errors);
        } catch (Exception e) {
            errors.add(Map.of("message", e.getMessage()));
            ResponseHandler.sendResponse(false
                                         , HttpStatus.INTERNAL_SERVER_ERROR
                                         , Strings.EMPTY
                                         , response
                                         , Optional.empty()
                                         , errors);
        }
    }
}
