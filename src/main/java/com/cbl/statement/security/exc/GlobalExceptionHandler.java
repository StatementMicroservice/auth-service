package com.cbl.statement.security.exc;

import com.cbl.statement.security.response.ResponseHandler;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.util.Strings;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.client.HttpClientErrorException;

import java.util.*;

@RestControllerAdvice
public class GlobalExceptionHandler {
    @ExceptionHandler(Exception.class)
    public final ResponseEntity<?> handleAllException(Exception ex) {

        var errors = new ArrayList<Map<String, String>>();
        errors.add(Map.of("message", ex.getMessage()));

        return ResponseHandler.generateResponse(false
                                                , HttpStatus.INTERNAL_SERVER_ERROR
                                                , StringUtils.EMPTY
                                                , Optional.empty()
                                                , errors);
    }

    @ExceptionHandler(RuntimeException.class)
    public final ResponseEntity<?> handleAllRuntimeException(RuntimeException ex) {

        var errors = new ArrayList<Map<String, String>>();
        errors.add(Map.of("message", ex.getMessage()));

        return ResponseHandler.generateResponse(false
                                                , HttpStatus.INTERNAL_SERVER_ERROR
                                                , StringUtils.EMPTY
                                                , Optional.empty()
                                                , errors);
    }

    @ExceptionHandler(AuthorizationDeniedException.class)
    public final ResponseEntity<?> authorizationDeniedException(AuthorizationDeniedException ex) {

        var errors = new ArrayList<Map<String, String>>();
        errors.add(Map.of("message", ex.getMessage()));

        return ResponseHandler.generateResponse(false
                                                , HttpStatus.FORBIDDEN
                                                , StringUtils.EMPTY
                                                , Optional.empty()
                                                , errors);
    }

    @ExceptionHandler(ValidationException.class)
    public ResponseEntity<?> validationException(ValidationException exception) {

        var errors = new ArrayList<Map<String, String>>();
        errors.add(exception.getValidationErrors());

        return ResponseHandler.generateResponse(false
                                                , HttpStatus.NOT_FOUND
                                                , StringUtils.EMPTY
                                                , Optional.empty()
                                                , errors);
    }

    @ExceptionHandler(TokenNotFoundException.class)
    public ResponseEntity<?> tokenNotFoundException(TokenNotFoundException ex) {

        var errors = new ArrayList<Map<String, String>>();
        errors.add(Map.of("message", ex.getMessage()));

        return ResponseHandler.generateResponse(false
                                                , HttpStatus.NOT_FOUND
                                                , StringUtils.EMPTY
                                                , Optional.empty()
                                                , errors);
    }

    @ExceptionHandler(UserNotFoundException.class)
    public ResponseEntity<?> userNotFoundException(UserNotFoundException ex) {

          var errors = new ArrayList<Map<String, String>>();
          errors.add(Map.of("message", ex.getMessage()));

        return ResponseHandler.generateResponse(false
                                                , HttpStatus.NOT_FOUND
                                                , StringUtils.EMPTY
                                                , Optional.empty()
                                                , errors);
    }

    @ExceptionHandler(IdentityException.class)
    public ResponseEntity<?> identityException(IdentityException ex) {

        var errors = new ArrayList<Map<String, String>>();
        errors.add(Map.of("message", ex.getMessage()));

        return ResponseHandler.generateResponse(false
                                                , ex.getHttpStatus()
                                                , StringUtils.EMPTY
                                                , Optional.empty()
                                                , errors);
    }

    @ExceptionHandler(MissingServletRequestParameterException.class)
    public ResponseEntity<?> handleMissingParams(MissingServletRequestParameterException ex) {

        var errors = new ArrayList<Map<String, String>>();
        errors.add(Map.of("message", ex.getMessage()));

        return ResponseHandler.generateResponse(false
                                                , HttpStatus.BAD_REQUEST
                                                , "Validation Error"
                                                , Optional.empty()
                                                , errors);
    }

    @ExceptionHandler(UsernameNotFoundException.class)
    public ResponseEntity<?> usernameNotFoundException(UsernameNotFoundException ex) {

        var errors = new ArrayList<Map<String, String>>();
        errors.add(Map.of("message", ex.getMessage()));

        return ResponseHandler.generateResponse(false
                , HttpStatus.NOT_FOUND
                , Strings.EMPTY
                , Optional.empty()
                , errors);
    }
}
