package com.cbl.statement.security.exc;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.UNAUTHORIZED)
public class AuthorizationHeaderNotFoundException extends RuntimeException {
    public AuthorizationHeaderNotFoundException(String message) {
        super(message);
    }
}
