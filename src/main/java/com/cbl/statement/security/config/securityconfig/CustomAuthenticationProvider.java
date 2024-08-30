package com.cbl.statement.security.config.securityconfig;

import com.cbl.statement.security.config.userconfig.UserInfoManagerConfig;
import com.cbl.statement.security.consts.ExceptionMsg;
import com.cbl.statement.security.exc.UserNotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Optional;

@Component
@Slf4j
@RequiredArgsConstructor
public class CustomAuthenticationProvider implements AuthenticationProvider {

    private final UserInfoManagerConfig userInfoManagerConfig;

    private final PasswordEncoder passwordEncoder;


    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        log.info("Starting authentication for user: {}", authentication.getName());

        String username = Optional.ofNullable(authentication.getName())
                                  .orElseThrow(() -> new BadCredentialsException(ExceptionMsg.INCORRECT_CREDENTIALS));
        String password = Optional.ofNullable(String.valueOf(authentication.getCredentials()))
                                  .orElseThrow(() -> new BadCredentialsException(ExceptionMsg.INCORRECT_CREDENTIALS));

        try {
            UserDetails userDetails = userInfoManagerConfig.loadUserByUsername(username);

            if (!passwordEncoder.matches(password, userDetails.getPassword())) {
                throw new BadCredentialsException(ExceptionMsg.INCORRECT_CREDENTIALS);
            }

            return new UsernamePasswordAuthenticationToken(userDetails, password, userDetails.getAuthorities());

        } catch (UsernameNotFoundException e) {
            throw new UserNotFoundException(String.format(ExceptionMsg.USER_NOT_FOUND, username));
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
