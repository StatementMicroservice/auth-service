package com.cbl.statement.security.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotEmpty;

public record UserRegistrationDto(

        @NotEmpty(message = "User First Name must not be empty")
        String firstName,

        @NotEmpty(message = "User Last Name must not be empty")
        String lastName,

        @NotEmpty(message = "User Name must not be empty")
        String userName,

        @NotEmpty(message = "User email must not be empty") //Neither null nor 0 size
        @Email(message = "Invalid email format")
        String email,

        @NotEmpty(message = "User Password must not be empty")
        String password,

        @NotEmpty(message = "User Mobile must not be empty")
        String mobile,

        @NotEmpty(message = "User role must not be empty")
        String role
) {}