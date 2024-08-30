package com.cbl.statement.security.config.appconfig;


import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Data
@Configuration
@ConfigurationProperties(prefix = "auth-service")
public class AppConfig {
    private String serverPort;
    private String activeProfile;
    private String testValue;
    private String jwtSecret;
    private String accessTokenExpiry;
    private String refreshTokenExpiry;
}
