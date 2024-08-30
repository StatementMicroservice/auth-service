package com.cbl.statement.security.mapper;

import com.cbl.statement.security.dto.UserRegistrationDto;
import com.cbl.statement.security.entity.Role;
import com.cbl.statement.security.entity.User;
import com.cbl.statement.security.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.Collections;

@Component
@RequiredArgsConstructor
public class UserMapper {
    private final PasswordEncoder passwordEncoder;
    private final RoleRepository roleRepository;

    public User convertToEntity(UserRegistrationDto userRegistrationDto) {
        final Collection<Role> roles = getRoles(userRegistrationDto.role());

        return User.builder()
                   .firstName(userRegistrationDto.firstName())
                   .lastName(userRegistrationDto.lastName())
                   .userName(userRegistrationDto.userName())
                   .email(userRegistrationDto.email())
                   .password(passwordEncoder.encode(userRegistrationDto.password()))
                   .mobile(userRegistrationDto.mobile())
                   .enabled(true)
                   .roles(roles)
                   .build();
    }

    private Collection<Role> getRoles(String roleName) {
        final Role role = roleRepository.findByName(roleName)
                                  .orElseThrow(() -> new RuntimeException(String.format("User roles: %s doesn't exists in DB.", roleName)));
        return Collections.singletonList(role);

    }
}
