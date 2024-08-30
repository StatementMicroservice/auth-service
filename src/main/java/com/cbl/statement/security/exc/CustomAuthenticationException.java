package com.cbl.statement.security.exc;

import org.springframework.security.core.userdetails.UsernameNotFoundException;

public class CustomAuthenticationException extends UsernameNotFoundException {
    public CustomAuthenticationException(String message) {
        super(message);
    }

    public CustomAuthenticationException(String message, Throwable cause) {
        super(message, cause);
    }
}
