package com.cbl.statement.security.service;

import com.cbl.statement.security.config.appconfig.AppConfig;
import com.cbl.statement.security.config.securityconfig.jwtconfig.JwtTokenGenerator;
import com.cbl.statement.security.consts.AppConstant;
import com.cbl.statement.security.consts.ExceptionMsg;
import com.cbl.statement.security.dto.AuthResponseDto;
import com.cbl.statement.security.dto.PrivilegeDto;
import com.cbl.statement.security.dto.RoleDto;
import com.cbl.statement.security.dto.UserRegistrationDto;
import com.cbl.statement.security.entity.Privilege;
import com.cbl.statement.security.entity.RefreshToken;
import com.cbl.statement.security.entity.Role;
import com.cbl.statement.security.entity.User;
import com.cbl.statement.security.exc.IdentityException;
import com.cbl.statement.security.exc.TokenNotFoundException;
import com.cbl.statement.security.exc.UserNotFoundException;
import com.cbl.statement.security.mapper.PrivilegeMapper;
import com.cbl.statement.security.mapper.RoleMapper;
import com.cbl.statement.security.mapper.UserMapper;
import com.cbl.statement.security.repository.PrivilegeRepository;
import com.cbl.statement.security.repository.RefreshTokenRepository;
import com.cbl.statement.security.repository.RoleRepository;
import com.cbl.statement.security.repository.UserRepository;
import com.cbl.statement.security.request.AuthRequest;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.time.temporal.ChronoUnit;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private static final long DAY_TO_SEC = ChronoUnit.DAYS.getDuration().toSeconds();
    private static final long MIN_TO_SEC = ChronoUnit.MINUTES.getDuration().toSeconds();

    private final UserRepository userRepository;
    private final PrivilegeRepository privilegeRepository;
    private final RoleRepository roleRepository;
    private final JwtTokenGenerator jwtTokenGenerator;
    private final RefreshTokenRepository refreshTokenRepository;
    private final UserMapper userMapper;
    private final PrivilegeMapper privilegeMapper;
    private final RoleMapper roleMapper;
    private final AppConfig appConfig;
    private final AuthenticationManager authManager;
    private final ObjectMapper objectMapper;

    public AuthResponseDto getJwtTokensAfterAuthentication(Authentication authentication, HttpServletResponse response) {
        final var userInfoEntity = userRepository.findByEmail(authentication.getName())
                                                 .orElseThrow(() -> {
                                                     log.error("[AuthService:userSignInAuth] User :{} not found", authentication.getName());
                                                     return new UserNotFoundException(String.format(ExceptionMsg.USER_NOT_FOUND_REGISTER, authentication.getName()));
                                                 });

        final String accessToken = jwtTokenGenerator.generateAccessToken(authentication);
        final String refreshToken = jwtTokenGenerator.generateRefreshToken(authentication);

        createRefreshTokenCookie(response, refreshToken);
        saveUserRefreshToken(userInfoEntity, refreshToken);

        log.info("[AuthService:userSignInAuth] Access token for user:{}, has been generated", userInfoEntity.getUserName());
        return AuthResponseDto.builder()
                              .accessToken(accessToken)
                              .accessTokenExpiry(Long.parseLong(appConfig.getAccessTokenExpiry()) * MIN_TO_SEC)
                              .refreshTokenExpiry(Long.parseLong(appConfig.getRefreshTokenExpiry()) * DAY_TO_SEC)
                              .userName(userInfoEntity.getUserName())
                              .tokenType(OAuth2AccessToken.TokenType.BEARER)
                              .build();
    }

    public Object geAccessTokenUsingRefreshToken(String authorizationHeader) {
        if (!authorizationHeader.startsWith(OAuth2AccessToken.TokenType.BEARER.getValue())) {
            return new IdentityException(HttpStatus.INTERNAL_SERVER_ERROR, ExceptionMsg.VERIFY_TOKEN_TYPE);
        }

        final String refreshToken = authorizationHeader.substring(7);
        final var refreshTokenEntity = refreshTokenRepository.findByRefreshToken(refreshToken)
                                                             .filter(tokens -> !tokens.isRevoked())
                                                             .orElseThrow(() -> new TokenNotFoundException(ExceptionMsg.REFRESH_TOKEN_NOT_FOUND));

        final User user = refreshTokenEntity.getUser();
        final Authentication authentication = createAuthenticationObject(user);

        final String accessToken = jwtTokenGenerator.generateAccessToken(authentication);

        return AuthResponseDto.builder()
                              .accessToken(accessToken)
                              .accessTokenExpiry(Long.parseLong(appConfig.getAccessTokenExpiry()) * MIN_TO_SEC)
                              .refreshTokenExpiry(Long.parseLong(appConfig.getRefreshTokenExpiry()) * DAY_TO_SEC)
                              .userName(user.getUserName())
                              .tokenType(OAuth2AccessToken.TokenType.BEARER)
                              .build();
    }

    public AuthResponseDto registerUser(UserRegistrationDto userRegistrationDto, HttpServletResponse httpServletResponse) {
        try {
            log.info("[AuthService:registerUser]User Registration Started with :::{}", userRegistrationDto);
            final Optional<User> user = userRepository.findByEmail(userRegistrationDto.email());
            if (user.isPresent()) {
                throw new IdentityException(HttpStatus.CONFLICT, ExceptionMsg.USER_ALREADY_EXIST);
            }

            final User userDetailsEntity = userMapper.convertToEntity(userRegistrationDto);
            final Authentication authentication = createAuthenticationObject(userDetailsEntity);

            final String accessToken = jwtTokenGenerator.generateAccessToken(authentication);
            final String refreshToken = jwtTokenGenerator.generateRefreshToken(authentication);

            final User savedUserDetails = userRepository.save(userDetailsEntity);
            saveUserRefreshToken(userDetailsEntity, refreshToken);

            createRefreshTokenCookie(httpServletResponse, refreshToken);

            log.info("[AuthService:registerUser] User:{} Successfully registered", savedUserDetails.getUserName());
            return AuthResponseDto.builder()
                                  .accessToken(accessToken)
                                  .accessTokenExpiry(Long.parseLong(appConfig.getAccessTokenExpiry()) * MIN_TO_SEC)
                                  .refreshTokenExpiry(Long.parseLong(appConfig.getRefreshTokenExpiry()) * DAY_TO_SEC)
                                  .userName(savedUserDetails.getUserName())
                                  .tokenType(OAuth2AccessToken.TokenType.BEARER)
                                  .build();


        } catch (Exception e) {
            log.error("[AuthService:registerUser]Exception while registering the user due to :" + e.getMessage());
            throw new IdentityException(HttpStatus.BAD_REQUEST, e.getMessage());
        }
    }

    public AuthResponseDto authenticateUser(AuthRequest request, HttpServletResponse response) throws JsonProcessingException {

        log.info("Enter authenticateUser of UserService with : " + objectMapper.writeValueAsString(request));
        if (!(StringUtils.hasText(request.getUsername()) || StringUtils.hasText(request.getPassword()))) {
            throw new IdentityException(HttpStatus.BAD_REQUEST, ExceptionMsg.CREDENTIALS_REQUIRED);
        }

        final UsernamePasswordAuthenticationToken authToken =
                new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword());

        final Authentication authentication = authManager.authenticate(authToken);
        return getJwtTokensAfterAuthentication(authentication, response);
    }

    public void setupPrivilege(PrivilegeDto privilegeDto) {
        final Optional<Privilege> privilege = privilegeRepository.findByName(privilegeDto.getPrivilege());
        if (privilege.isPresent()) {
            throw new IdentityException(HttpStatus.CONFLICT, String.format(ExceptionMsg.PRIVILEGE_ALREADY_EXIST
                                                           , privilegeDto.getPrivilege()));
        }
        final Privilege privilegeEntity = privilegeMapper.convertToEntity(privilegeDto);
        privilegeRepository.save(privilegeEntity);
    }

    public void setupRole(RoleDto roleDto) {
        final Optional<Role> role = roleRepository.findByName(roleDto.getRole());
        if (role.isPresent()) {
            throw new IdentityException(HttpStatus.CONFLICT, String.format(ExceptionMsg.ROLE_ALREADY_EXIST
                    , roleDto.getRole()));
        }
        final Role roleEntity = roleMapper.convertToEntity(roleDto);
        roleRepository.save(roleEntity);
    }

    private void createRefreshTokenCookie(HttpServletResponse response, String refreshToken) {
        final Cookie refreshTokenCookie = new Cookie(AppConstant.REFRESH_TOKEN, refreshToken);
        refreshTokenCookie.setHttpOnly(true);
        refreshTokenCookie.setSecure(true);
        refreshTokenCookie.setMaxAge(Math.toIntExact(Long.parseLong(appConfig.getRefreshTokenExpiry()) * DAY_TO_SEC));

        response.addCookie(refreshTokenCookie);
    }

    private void saveUserRefreshToken(User user, String refreshToken) {
        final var refreshTokenEntity = RefreshToken.builder()
                                             .refreshToken(refreshToken)
                                             .revoked(false)
                                             .user(user)
                                             .build();

        refreshTokenRepository.save(refreshTokenEntity);
    }

    private Authentication createAuthenticationObject(User user) {
        final String username = user.getEmail();
        final String password = user.getPassword();
        final Collection<Role> roles = user.getRoles();

        final List<GrantedAuthority> authorities = roles.stream()
                                                  .map(role -> new SimpleGrantedAuthority(role.getName()))
                                                  .collect(Collectors.toList());

        return new UsernamePasswordAuthenticationToken(username, password, authorities);
    }
}
