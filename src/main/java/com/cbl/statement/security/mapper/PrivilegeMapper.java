package com.cbl.statement.security.mapper;

import com.cbl.statement.security.dto.PrivilegeDto;
import com.cbl.statement.security.entity.Privilege;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class PrivilegeMapper {

    public Privilege convertToEntity(PrivilegeDto privilegeDto) {
        return Privilege.builder()
                .name(privilegeDto.getPrivilege())
                .build();
    }
}
