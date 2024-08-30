package com.cbl.statement.security.config.userconfig;

import com.cbl.statement.security.consts.ExceptionMsg;
import com.cbl.statement.security.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

    @Service
    @RequiredArgsConstructor
    public class UserInfoManagerConfig implements UserDetailsService {

    private final UserRepository userRepository;
    @Override
    public UserDetails loadUserByUsername(String emailId) throws UsernameNotFoundException {
        return userRepository.findByEmail(emailId)
                             .map(UserInfoConfig::new)
                             .orElseThrow(()-> new UsernameNotFoundException(String.format(ExceptionMsg.USER_NOT_FOUND, emailId)));
    }
}
