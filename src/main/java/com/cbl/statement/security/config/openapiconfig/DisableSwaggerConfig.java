package com.cbl.statement.security.config.openapiconfig;

import com.cbl.statement.security.config.profileconfig.ConditionalOnProfile;
import com.cbl.statement.security.enums.EnvironmentProfile;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@ConditionalOnProfile({EnvironmentProfile.PROD
                       , EnvironmentProfile.QA
                       , EnvironmentProfile.UAT})
@Configuration
public class DisableSwaggerConfig implements WebMvcConfigurer {
    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        registry.addResourceHandler("/city-statement/auth/v3/api-docs").addResourceLocations("classpath:/no-swagger/");
        registry.addResourceHandler("/city-statement/auth/v3/api-docs.yml")
                .addResourceLocations("classpath:/no-swagger/");
        registry.addResourceHandler("/city-statement/auth/v3/api-docs/**")
                .addResourceLocations("classpath:/no-swagger/");
        registry.addResourceHandler("/city-statement/auth/swagger-resources")
                .addResourceLocations("classpath:/no-swagger/");
        registry.addResourceHandler("/city-statement/auth/swagger-resources/**")
                .addResourceLocations("classpath:/no-swagger/");
        registry.addResourceHandler("/city-statement/auth/swagger-ui").addResourceLocations("classpath:/no-swagger/");
        registry.addResourceHandler("/city-statement/auth/swagger-ui.html")
                .addResourceLocations("classpath:/no-swagger/");
        registry.addResourceHandler("/city-statement/auth/swagger-ui/index.html")
                .addResourceLocations("classpath:/no-swagger/");
    }
}
