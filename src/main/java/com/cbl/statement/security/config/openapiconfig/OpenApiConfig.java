package com.cbl.statement.security.config.openapiconfig;

import com.cbl.statement.security.config.appconfig.AppConfig;
import com.cbl.statement.security.config.profileconfig.ConditionalOnProfile;
import com.cbl.statement.security.dto.OpenApiPropertyDto;
import com.cbl.statement.security.enums.EnvironmentProfile;
import com.cbl.statement.security.util.HostAddressUtil;
import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.servers.Server;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;
import java.util.Optional;

import static io.swagger.v3.oas.models.security.SecurityScheme.In.HEADER;
import static io.swagger.v3.oas.models.security.SecurityScheme.Type.HTTP;

@ConditionalOnProfile(EnvironmentProfile.DEV)
@Configuration
@RequiredArgsConstructor
public class OpenApiConfig {

    private static final String HOST = Optional.ofNullable(HostAddressUtil.getHostAddress()).orElse("localhost");
    private final OpenApiProperty openApiProperties;
    private final AppConfig appConfig;

    @Bean
    public OpenAPI customOpenApiConfig() {
        var openApiProperties = getOpenApiProperties();
        var contactName = openApiProperties.getContactName();
        var contactEmail = openApiProperties.getContactEmail();
        var contactUrl = openApiProperties.getContactUrl();
        var title = openApiProperties.getTitle();
        var version = openApiProperties.getVersion();
        var envDescription = openApiProperties.getEnvDescription();
        var description = openApiProperties.getDescription();
        var licenseName = openApiProperties.getLicenseName();
        var licenseUrl = openApiProperties.getLicenseUrl();
        var termsOfService = openApiProperties.getTermsOfService();
        var bearerTokenSecurity = openApiProperties.getBearerTokenSecurity();
        var basicAuthSecurity = getOpenApiProperties().getBasicAuthSecurity();
        var bearerTokenComponent = openApiProperties.getBearerTokenComponent();
        var basicAuthComponent = openApiProperties.getBasicAuthComponent();
        var url = openApiProperties.getProtocol() + "://" + HOST + ":" + openApiProperties.getPort();

        if (appConfig.getActiveProfile().equals(EnvironmentProfile.DEV.getProfile())) {
            Server devServer = new Server();
            devServer.setDescription(envDescription);
            devServer.setUrl(url);

            return new OpenAPI()
                    .addServersItem(devServer)
                    .info(new Info()
                            .contact(new Contact()
                                    .name(contactName)
                                    .email(contactEmail)
                                    .url(contactUrl))
                            .title(title)
                            .version(version)
                            .description(description)
                            .license(new License()
                                    .name(licenseName)
                                    .url(licenseUrl))
                            .termsOfService(termsOfService))
                    .security(getSecurityRequirementList(bearerTokenSecurity, basicAuthSecurity))
                    .components(new Components()
                            .addSecuritySchemes(bearerTokenComponent, getBearerTokenScheme())
                            .addSecuritySchemes(basicAuthComponent, getBasicAuthScheme()));
        }
        return null;
    }

    private OpenApiPropertyDto getOpenApiProperties() {
        var env = Optional.ofNullable(appConfig.getActiveProfile())
                          .orElse(EnvironmentProfile.DEV.getProfile());
        var protocol = Optional.ofNullable(openApiProperties.getServer().getProtocol())
                               .orElse("http");
        var port = Optional.ofNullable(appConfig.getServerPort())
                           .orElse("8080");
        var envDescription = Optional.ofNullable(openApiProperties.getServer().getEnvDescription())
                                     .orElse("Development");
        var contactName = Optional.ofNullable(openApiProperties.getInfo().getContact().getName())
                                  .orElse("CBL");
        var contactEmail = Optional.ofNullable(openApiProperties.getInfo().getContact().getEmail())
                                   .orElse("https://www.cbl.com");
        var contactUrl = Optional.ofNullable(openApiProperties.getInfo().getContact().getUrl())
                                 .orElse("test@example.com");
        var title = Optional.ofNullable(openApiProperties.getInfo().getTitle())
                            .orElse("City Statement Auth Service");
        var version = Optional.ofNullable(openApiProperties.getInfo().getVersion())
                              .orElse("1.0");
        var description = Optional.ofNullable(openApiProperties.getInfo().getDescription())
                                  .orElse("City Statement Auth API");
        var licenseName = Optional.ofNullable(openApiProperties.getInfo().getLicense().getName())
                                  .orElse("Apache 2.0");
        var licenseUrl = Optional.ofNullable(openApiProperties.getInfo().getLicense().getUrl())
                                 .orElse("http://www.apache.org/licenses/LICENSE-2.0.html");
        var termsOfService = Optional.ofNullable(openApiProperties.getInfo().getTermsOfService())
                                     .orElse("http://swagger.io/terms/");
        var bearerTokenSecurity = Optional.ofNullable(openApiProperties.getSecurity().getBearerToken())
                                          .orElse("Bearer Token");
        var basicAuthSecurity = Optional.ofNullable(openApiProperties.getSecurity().getBasicAuth())
                                        .orElse("Basic Authentication");
        var descriptionSecurity = Optional.ofNullable(openApiProperties.getSecurity().getDescription())
                                          .orElse("JWT Authentication");
        var schemeSecurity = Optional.ofNullable(openApiProperties.getSecurity().getScheme())
                                     .orElse("bearer");
        var bearerFormatSecurity = Optional.ofNullable(openApiProperties.getSecurity().getBasicAuth())
                                           .orElse("JWT");
        var bearerTokenComponent = Optional.ofNullable(openApiProperties.getComponent().getBearerToken())
                                           .orElse("Bearer Token");
        var basicAuthComponent = Optional.ofNullable(openApiProperties.getComponent().getBasicAuth())
                                         .orElse("Basic Authentication");
        var descriptionComponent = Optional.ofNullable(openApiProperties.getComponent().getDescription())
                                           .orElse("JWT Authentication");
        var schemeComponent = Optional.ofNullable(openApiProperties.getComponent().getScheme())
                                      .orElse("basic");

        return OpenApiPropertyDto.builder()
                                 .env(env)
                                 .protocol(protocol)
                                 .port(port)
                                 .envDescription(envDescription)
                                 .contactName(contactName)
                                 .contactEmail(contactEmail)
                                 .contactUrl(contactUrl)
                                 .title(title)
                                 .version(version)
                                 .description(description)
                                 .licenseName(licenseName)
                                 .licenseUrl(licenseUrl)
                                 .termsOfService(termsOfService)
                                 .bearerTokenSecurity(bearerTokenSecurity)
                                 .basicAuthSecurity(basicAuthSecurity)
                                 .descriptionSecurity(descriptionSecurity)
                                 .schemeSecurity(schemeSecurity)
                                 .bearerFormatSecurity(bearerFormatSecurity)
                                 .bearerTokenComponent(bearerTokenComponent)
                                 .basicAuthComponent(basicAuthComponent)
                                 .descriptionComponent(descriptionComponent)
                                 .schemeComponent(schemeComponent)
                                 .build();
    }

    private SecurityScheme getBearerTokenScheme() {
        var openApiProperties = getOpenApiProperties();
        var bearerTokenSecurity = openApiProperties.getBearerTokenSecurity();
        var descriptionSecurity = openApiProperties.getDescriptionSecurity();
        var schemeSecurity = openApiProperties.getSchemeSecurity();
        var bearerFormatSecurity = openApiProperties.getBearerFormatSecurity();
        return new SecurityScheme()
                .name(bearerTokenSecurity)
                .description(descriptionSecurity)
                .scheme(schemeSecurity)
                .type(HTTP)
                .bearerFormat(bearerFormatSecurity)
                .in(HEADER);
    }

    private SecurityScheme getBasicAuthScheme() {
        var openApiProperties = getOpenApiProperties();
        var bearerTokenComponent = openApiProperties.getBearerTokenComponent();
        var descriptionComponent = openApiProperties.getDescriptionComponent();
        var schemeComponent = openApiProperties.getSchemeComponent();

        return new SecurityScheme()
                .name(bearerTokenComponent)
                .description(descriptionComponent)
                .scheme(schemeComponent)
                .type(HTTP)
                .in(HEADER);
    }

    private List<SecurityRequirement> getSecurityRequirementList(String bearerToken, String basicAuth) {
        SecurityRequirement bearerTokenRequirement = new SecurityRequirement().addList(bearerToken);
        SecurityRequirement basicAuthRequirement = new SecurityRequirement().addList(basicAuth);
        return List.of(bearerTokenRequirement, basicAuthRequirement);
    }
}
