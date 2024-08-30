package com.cbl.statement.security.config.openapiconfig;


import com.cbl.statement.security.config.profileconfig.ConditionalOnProfile;
import com.cbl.statement.security.enums.EnvironmentProfile;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@ConditionalOnProfile(EnvironmentProfile.DEV)
@Data
@Configuration
@ConfigurationProperties(prefix = "openapi")
public class OpenApiProperty {
    private Server server;
    private Info info;
    private Security security;
    private Component component;

    @Data
    public static class Server {
        private String envDescription;
        private String protocol;
        private String serviceName;
    }

    @Data
    public static class Info {
        private Contact contact;
        private String title;
        private String version;
        private String description;
        private License license;
        private String termsOfService;

        @Data
        public static class Contact {
            private String name;
            private String email;
            private String url;
        }

        @Data
        public static class License {
            private String name;
            private String url;
        }
    }

    @Data
    public static class Security {
        private String bearerToken;
        private String basicAuth;
        private String description;
        private String scheme;
        private String bearerFormat;
    }

    @Data
    public static class Component {
        private String bearerToken;
        private String basicAuth;
        private String description;
        private String scheme;
    }
}
