package com.cbl.statement.security.config.securityconfig;

import com.cbl.statement.security.consts.ExceptionMsg;
import com.cbl.statement.security.exc.CustomAuthenticationException;
import com.cbl.statement.security.response.ResponseHandler;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.lang3.StringUtils;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Map;
import java.util.Optional;

@Component
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response
                       , AuthenticationException authException) throws IOException, ServletException {
        var errors = new ArrayList<Map<String, String>>();

        if (authException instanceof BadCredentialsException || authException instanceof CustomAuthenticationException) {

            errors.add(Map.of("message", authException.getMessage()));
            ResponseHandler.sendResponse(false
                                        , HttpStatus.UNAUTHORIZED
                                        , StringUtils.EMPTY
                                        , response
                                        , Optional.empty()
                                        , errors);
        } else {
            errors.add(Map.of("message", ExceptionMsg.AUTHENTICATION_FAILED));
            ResponseHandler.sendResponse(false
                                        , HttpStatus.UNAUTHORIZED
                                        , StringUtils.EMPTY
                                        , response
                                        , Optional.empty()
                                        ,errors);
        }
    }
}
