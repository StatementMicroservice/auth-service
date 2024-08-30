package com.cbl.statement.security.exc;


import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
public class IdentityException extends RuntimeException {
    private final HttpStatus httpStatus;

    public IdentityException(HttpStatus httpStatus, String message) {
        super(message);
        this.httpStatus = httpStatus;
    }
}
