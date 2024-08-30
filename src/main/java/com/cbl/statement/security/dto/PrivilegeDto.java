package com.cbl.statement.security.dto;

import jakarta.validation.constraints.NotEmpty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class PrivilegeDto {

    @NotEmpty(message = "Privilege Name must not be empty")
    private String privilege;
}
