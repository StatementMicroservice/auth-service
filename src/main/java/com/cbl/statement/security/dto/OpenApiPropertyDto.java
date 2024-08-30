package com.cbl.statement.security.dto;

import com.cbl.statement.security.config.profileconfig.ConditionalOnProfile;
import com.cbl.statement.security.enums.EnvironmentProfile;
import lombok.Builder;
import lombok.Data;

@ConditionalOnProfile(EnvironmentProfile.DEV)
@Data
@Builder
public class OpenApiPropertyDto {
    private String env;
    private String protocol;
    private String port;
    private String envDescription;
    private String contactName;
    private String contactEmail;
    private String contactUrl;
    private String title;
    private String version;
    private String description;
    private String licenseName;
    private String licenseUrl;
    private String termsOfService;
    private String bearerTokenSecurity;
    private String basicAuthSecurity;
    private String descriptionSecurity;
    private String schemeSecurity;
    private String bearerFormatSecurity;
    private String bearerTokenComponent;
    private String basicAuthComponent;
    private String descriptionComponent;
    private String schemeComponent;
}
