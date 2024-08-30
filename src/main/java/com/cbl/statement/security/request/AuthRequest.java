package com.cbl.statement.security.request;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;

@AllArgsConstructor
@Getter
@Setter
@Data
public class AuthRequest {

    @NotBlank(message = "username is mandatory")
    private String username;

    @NotBlank(message = "Password is mandatory")
    private String password;
}
