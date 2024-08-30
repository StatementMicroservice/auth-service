package com.cbl.statement.security.controller;

import com.cbl.statement.security.consts.ResponseMsg;
import com.cbl.statement.security.dto.PrivilegeDto;
import com.cbl.statement.security.dto.RoleDto;
import com.cbl.statement.security.dto.UserRegistrationDto;
import com.cbl.statement.security.request.AuthRequest;
import com.cbl.statement.security.response.ResponseHandler;
import com.cbl.statement.security.service.AuthService;
import com.cbl.statement.security.util.UrlUtility;
import com.fasterxml.jackson.core.JsonProcessingException;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.jetbrains.annotations.NotNull;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.util.*;

@RestController
@RequiredArgsConstructor
@Slf4j
@RequestMapping(UrlUtility.AUTH_CONTROLLER)
public class AuthController {
    private final AuthService authService;

    @PostMapping("/sign-in")
    public ResponseEntity<?> authenticateUser(@RequestBody @Valid AuthRequest request, BindingResult bindingResult
                                            , HttpServletResponse response) throws JsonProcessingException {

        if (bindingResult.hasErrors()) {
            var errors = getErrors(bindingResult);
            log.error("[AuthController:registerUser]Errors in user:{}", errors);
            return ResponseHandler.generateResponse(false
                                                    , HttpStatus.BAD_REQUEST
                                                    , StringUtils.EMPTY
                                                    , Optional.empty()
                                                    , errors);
        }
        var authResponseDto = authService.authenticateUser(request, response);
        return ResponseHandler.generateResponse(true
                                                 , HttpStatus.OK
                                                 , ResponseMsg.SUCCESSFUL_SIGN_IN
                                                 , authResponseDto
                                                 , Collections.emptyList());
    }

    @PreAuthorize("hasAuthority('SCOPE_REFRESH_TOKEN')")
    @PostMapping("/refresh-token")
    public ResponseEntity<?> getAccessToken(@RequestHeader(HttpHeaders.AUTHORIZATION) String authorizationHeader) {
        var responseObj = authService.geAccessTokenUsingRefreshToken(authorizationHeader);
        return ResponseHandler.generateResponse(true
                                                , HttpStatus.OK
                                                , ResponseMsg.SUCCESSFUL_TOKEN_GENERATION
                                                , responseObj
                                                , Collections.emptyList());
    }

    @PostMapping("/sign-up")
    public ResponseEntity<?> registerUser(@Valid @RequestBody UserRegistrationDto userRegistrationDto,
                                          BindingResult bindingResult, HttpServletResponse response) throws IOException {

        log.info("[AuthController:registerUser] Signup Process Started for user:{}", userRegistrationDto.userName());
        if (bindingResult.hasErrors()) {
            var errors = getErrors(bindingResult);
            log.error("[AuthController:registerUser]Errors in user:{}", errors);
            return ResponseHandler.generateResponse(false
                                                    , HttpStatus.BAD_REQUEST
                                                    , StringUtils.EMPTY
                                                    , Optional.empty()
                                                    , errors);
        }
        var authResponseDto = authService.registerUser(userRegistrationDto, response);
        return ResponseHandler.generateResponse(true
                                                , HttpStatus.OK
                                                , ResponseMsg.SUCCESSFUL_REGISTRATION
                                                , authResponseDto
                                                , Collections.emptyList());
    }

    @PostMapping("/setup-privilege")
    public ResponseEntity<?> setupPrivilege(@Valid @RequestBody PrivilegeDto privilegeDto,
                                            BindingResult bindingResult, HttpServletResponse response) throws IOException {

        log.info("Privileges setup Process Started:{}", privilegeDto);
        if (bindingResult.hasErrors()) {
            var errors = getErrors(bindingResult);
            log.error("Privilege setup Errors:{}", errors);
            return ResponseHandler.generateResponse(false
                                                   , HttpStatus.BAD_REQUEST
                                                   , StringUtils.EMPTY
                                                   , Optional.empty()
                                                   , errors);
        }
        authService.setupPrivilege(privilegeDto);
        return ResponseHandler.generateResponse(true
                                               , HttpStatus.OK
                                               , ResponseMsg.PRIVILEGE_SETUP_SUCCESSFUL
                                               , Optional.empty()
                                               , Collections.emptyList());
    }

    @PostMapping("/setup-role")
    public ResponseEntity<?> setupRole(@Valid @RequestBody RoleDto roleDto,
                                       BindingResult bindingResult, HttpServletResponse response) throws IOException {

        log.info("Role setup Process Started:{}", roleDto);
        if (bindingResult.hasErrors()) {
            var errors = getErrors(bindingResult);
            log.error("Role setup Errors:{}", errors);
            return ResponseHandler.generateResponse(false
                                                   , HttpStatus.BAD_REQUEST
                                                   , StringUtils.EMPTY
                                                   , Optional.empty()
                                                   , errors);
        }
        authService.setupRole(roleDto);
        return ResponseHandler.generateResponse(true
                                               , HttpStatus.OK
                                               , ResponseMsg.ROLE_SETUP_SUCCESSFUL
                                               , Optional.empty()
                                               , Collections.emptyList());
    }

    @NotNull
    private static List<Map<String, String>> getErrors(BindingResult bindingResult) {
        return bindingResult.getFieldErrors().stream()
                            .map(error -> Map.of(
                                    "field", error.getField(),
                                    "message", Objects.requireNonNull(error.getDefaultMessage())))
                            .toList();
    }
}
