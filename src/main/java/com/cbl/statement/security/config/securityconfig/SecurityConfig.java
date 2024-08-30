package com.cbl.statement.security.config.securityconfig;

import com.cbl.statement.security.config.appconfig.AppConfig;
import com.cbl.statement.security.config.securityconfig.jwtconfig.JwtAccessTokenFilter;
import com.cbl.statement.security.config.securityconfig.jwtconfig.JwtRefreshTokenFilter;
import com.cbl.statement.security.config.securityconfig.jwtconfig.JwtTokenUtils;
import com.cbl.statement.security.repository.RefreshTokenRepository;
import com.cbl.statement.security.service.LogoutHandlerService;
import com.cbl.statement.security.util.UrlUtility;
import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import io.jsonwebtoken.io.Decoders;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.oauth2.server.resource.web.access.BearerTokenAccessDeniedHandler;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
@Slf4j
public class SecurityConfig {
    private static final String BASE_URL = UrlUtility.BASE_URL;
    private static final String BASE_URL_API = UrlUtility.BASE_URL_API;
    private static final String VERSION_1 = UrlUtility.VERSION_1;
    private static final String[] AUTH_WHITELIST = {
            BASE_URL + VERSION_1 + "/sign-up/**",
            BASE_URL + VERSION_1 + "/privilege/**",
            BASE_URL + VERSION_1 + "/role/**",
            UrlUtility.USER_DETAILS_CONTROLLER,
            BASE_URL + "/v3/api-docs",
            BASE_URL + "/v3/api-docs.yml",
            BASE_URL + "/v3/api-docs/**",
            BASE_URL + "/swagger-resources",
            BASE_URL + "/swagger-resources/**",
            BASE_URL + "/swagger-ui/**",
            BASE_URL + "/swagger-ui.html"
    };

    private final JwtTokenUtils jwtTokenUtils;
    private final RefreshTokenRepository refreshTokenRepository;
    private final LogoutHandlerService logoutHandlerService;
    private final AppConfig appConfig;
    private final CustomAuthenticationEntryPoint customAuthenticationEntryPoint;

    @Order(1)
    @Bean
    public SecurityFilterChain apiSecurityFilterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity
                       .securityMatcher(new AntPathRequestMatcher(BASE_URL_API + "/**"))
                       .csrf(AbstractHttpConfigurer::disable)
                       .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                       .oauth2ResourceServer(oauth2 -> oauth2.jwt(withDefaults()))
                       .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                       .addFilterBefore(new JwtAccessTokenFilter(jwtTokenUtils, jwtDecoder()), UsernamePasswordAuthenticationFilter.class)
                       .exceptionHandling(ex -> {
                           log.info("[SecurityConfig:apiSecurityFilterChain] Exception due to :{}", ex);
                           ex.authenticationEntryPoint(customAuthenticationEntryPoint);
                           ex.authenticationEntryPoint(new BearerTokenAuthenticationEntryPoint());
                           ex.accessDeniedHandler(new BearerTokenAccessDeniedHandler());
                       })
                       .build();
    }

    @Order(2)
    @Bean
    public SecurityFilterChain refreshTokenSecurityFilterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity
                       .securityMatcher(new AntPathRequestMatcher(BASE_URL + VERSION_1 + "/refresh-token/**"))
                       .csrf(AbstractHttpConfigurer::disable)
                       .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                       .oauth2ResourceServer(oauth2 -> oauth2.jwt(withDefaults()))
                       .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                       .addFilterBefore(new JwtRefreshTokenFilter(jwtTokenUtils, refreshTokenRepository, jwtDecoder()), UsernamePasswordAuthenticationFilter.class)
                       .exceptionHandling(ex -> {
                           log.info("[SecurityConfig:refreshTokenSecurityFilterChain] Exception due to :{}", ex);
                           ex.authenticationEntryPoint(customAuthenticationEntryPoint);
                           ex.authenticationEntryPoint(new BearerTokenAuthenticationEntryPoint());
                           ex.accessDeniedHandler(new BearerTokenAccessDeniedHandler());
                       })
                       .build();
    }

    @Order(3)
    @Bean
    public SecurityFilterChain logoutSecurityFilterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity
                       .securityMatcher(new AntPathRequestMatcher(BASE_URL + "/logout/**"))
                       .csrf(AbstractHttpConfigurer::disable)
                       .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                       .oauth2ResourceServer(oauth2 -> oauth2.jwt(withDefaults()))
                       .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                       .addFilterBefore(new JwtAccessTokenFilter(jwtTokenUtils, jwtDecoder()), UsernamePasswordAuthenticationFilter.class)
                       .logout(logout -> logout
                                                 .logoutUrl("/city-statement/auth/logout")
                                                 .addLogoutHandler(logoutHandlerService)
                                                 .logoutSuccessHandler(((request, response, authentication) -> SecurityContextHolder.clearContext()))
                       )
                       .exceptionHandling(ex -> {
                           log.info("[SecurityConfig:logoutSecurityFilterChain] Exception due to :{}", ex);
                           ex.authenticationEntryPoint(customAuthenticationEntryPoint);
                           ex.authenticationEntryPoint(new BearerTokenAuthenticationEntryPoint());
                           ex.accessDeniedHandler(new BearerTokenAccessDeniedHandler());
                       })
                       .build();
    }

    @Order(4)
    @Bean
    public SecurityFilterChain apiWhiteListFilterChain(HttpSecurity httpSecurity) throws Exception {
        RequestMatcher whiteListMatcher = createWhiteListMatcher();
        return httpSecurity
                       .securityMatcher(whiteListMatcher)
                       .csrf(AbstractHttpConfigurer::disable)
                       .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
                       .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                       .build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public JwtEncoder jwtEncoder() {
        byte[] secretByte = Decoders.BASE64.decode(appConfig.getJwtSecret());
        JWK jwk = new OctetSequenceKey
                              .Builder(secretByte)
                              .algorithm(Algorithm.parse(MacAlgorithm.HS256.getName()))
                              .build();

        JWKSource<SecurityContext> jwkSource = (jwkSelector, context) -> jwkSelector.select(new JWKSet(jwk));
        return new NimbusJwtEncoder(jwkSource);
    }

    @Bean
    public JwtDecoder jwtDecoder() {
        byte[] secretByte = Decoders.BASE64.decode(appConfig.getJwtSecret());
        SecretKey secretKey = new SecretKeySpec(secretByte, 0, secretByte.length, MacAlgorithm.HS256.getName());
        return NimbusJwtDecoder.withSecretKey(secretKey).macAlgorithm(MacAlgorithm.HS256).build();
    }

    private RequestMatcher createWhiteListMatcher() {
        var length = SecurityConfig.AUTH_WHITELIST.length;
        RequestMatcher[] matchers = new RequestMatcher[length];

        for (int i = 0; i < length; i++) {
            matchers[i] = new AntPathRequestMatcher(SecurityConfig.AUTH_WHITELIST[i]);
        }
        return new OrRequestMatcher(matchers);
    }
}
