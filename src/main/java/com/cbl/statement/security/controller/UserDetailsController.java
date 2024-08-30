package com.cbl.statement.security.controller;

import com.cbl.statement.security.config.securityconfig.jwtconfig.JwtTokenUtils;
import com.cbl.statement.security.response.ResponseHandler;
import com.cbl.statement.security.util.UrlUtility;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.logging.log4j.util.Strings;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collections;
import java.util.Optional;

@RestController
@RequiredArgsConstructor
@Slf4j
@RequestMapping(UrlUtility.USER_DETAILS_CONTROLLER)
public class UserDetailsController {

    private final JwtTokenUtils jwtTokenUtils;

    @GetMapping("/userinfo")
    public ResponseEntity<?> getUserDetails(@RequestParam(name = "emailId") String emailId) {
        final UserInfo userInfo = new UserInfo();
        final var userDetails = Optional.ofNullable(jwtTokenUtils.getUserDetailsWithoutThrowingException(emailId));
        userDetails.ifPresent(user -> userInfo.setUserName(user.getUsername()));
        log.info("UserInfo for emailId : {} is: {}", emailId,userInfo);

        return ResponseHandler.generateResponse(true
                                               , HttpStatus.OK
                                               , Strings.EMPTY
                                               , userInfo
                                               , Collections.emptyList());
    }

    @Data
    public static class UserInfo {
        private String userName;
    }
}
