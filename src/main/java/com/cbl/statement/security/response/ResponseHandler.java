package com.cbl.statement.security.response;

import com.cbl.statement.security.util.CommonUtility;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

import java.io.IOException;
import java.util.*;

public class ResponseHandler {
    private static final Map<String, Object> responseBody = new LinkedHashMap<>();

    private ResponseHandler() {
    }

    public static ResponseEntity<?> generateResponse(Boolean isSuccess, HttpStatus httpStatus
                                                   , String message, Object responseObj, List<Map<String, String>> errors) {

        responseBody.put("success", isSuccess);
        responseBody.put("code", httpStatus.value());
        responseBody.put("title", httpStatus.getReasonPhrase());
        responseBody.put("message", message);

        if (responseObj instanceof Optional<?> optional) {
            responseBody.put("data", optional.isPresent() ? optional.get() : new Object[0]);
        } else {
            responseBody.put("data", !Objects.isNull(responseObj) ? responseObj : new Object[0]);
        }
        responseBody.put("errors", errors);
        return new ResponseEntity<>(responseBody, httpStatus);
    }


    public static void sendResponse(Boolean isSuccess, HttpStatus httpStatus, String message, HttpServletResponse response
            , Object responseObj, List<Map<String, String>> errors) throws IOException {

        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        responseBody.put("success", isSuccess);
        responseBody.put("code", httpStatus.value());
        responseBody.put("title", httpStatus.getReasonPhrase());
        responseBody.put("message", message);

        if (responseObj instanceof Optional<?> optional) {
            responseBody.put("data", optional.isPresent() ? optional.get() : new Object[0]);
        } else {
            responseBody.put("data", !Objects.isNull(responseObj) ? responseObj : new Object[0]);
        }
        responseBody.put("errors", errors);

        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.writeValue(response.getWriter(), responseBody);
    }
}
