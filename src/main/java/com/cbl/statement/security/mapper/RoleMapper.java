package com.cbl.statement.security.mapper;

import com.cbl.statement.security.dto.RoleDto;
import com.cbl.statement.security.entity.Privilege;
import com.cbl.statement.security.entity.Role;
import com.cbl.statement.security.repository.PrivilegeRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.List;

@Component
@RequiredArgsConstructor
public class RoleMapper {

    private final PrivilegeRepository privilegeRepository;

    public Role convertToEntity(RoleDto roleDto) {
        final List<String> privilegesFromReq = roleDto.getPrivileges();
        final Collection<Privilege> privileges = privilegeRepository.findAllByNameIn(privilegesFromReq);

        return Role.builder()
                   .name(roleDto.getRole())
                   .privileges(privileges)
                   .build();
    }
}
