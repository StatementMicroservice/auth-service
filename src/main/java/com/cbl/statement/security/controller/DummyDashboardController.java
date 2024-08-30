package com.cbl.statement.security.controller;

import com.cbl.statement.security.config.appconfig.AppConfig;
import com.cbl.statement.security.util.UrlUtility;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;

@RestController
@RefreshScope
@RequiredArgsConstructor
@RequestMapping(UrlUtility.DUMMY_DASHBOARD_CONTROLLER)
public class DummyDashboardController {
    private static final Logger log = LoggerFactory.getLogger("dashboardLogger");

    private final AppConfig appConfig;

    //@PreAuthorize("hasAnyRole('ROLE_MANAGER','ROLE_ADMIN','ROLE_USER')") //Role based authentication
    @PreAuthorize("hasAuthority('SCOPE_READ')")
    @GetMapping("/welcome-message")
    public ResponseEntity<String> getFirstWelcomeMessage(Authentication authentication) {
        return ResponseEntity.ok("Welcome to the JWT authentication/authorization. [city-statement-auth-service]:" + authentication.getName() + "with scope:" + authentication.getAuthorities());
    }

    //@PreAuthorize("hasRole('ROLE_MANAGER')")
    @PreAuthorize("hasAuthority('SCOPE_READ')")
    @GetMapping("/manager-message")
    public ResponseEntity<String> getManagerData(Principal principal) {
        log.info("Manager name is :: {}", principal.getName());
        return ResponseEntity.ok("Manager::" + principal.getName() + " [city-statement-auth-service] . " + appConfig.getTestValue());

    }

    //@PreAuthorize("hasRole('ROLE_ADMIN')")
    @PreAuthorize("hasAuthority('SCOPE_WRITE') and hasRole('ROLE_ADMIN')")
    @PostMapping("/admin-message")
    public ResponseEntity<String> getAdminData(@RequestParam("message") String message, Principal principal) {
        return ResponseEntity.ok("Admin::" + principal.getName() + " has this message:" + message);
    }
}
