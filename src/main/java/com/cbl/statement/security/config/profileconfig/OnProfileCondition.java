package com.cbl.statement.security.config.profileconfig;

import com.cbl.statement.security.enums.EnvironmentProfile;
import org.springframework.context.annotation.Condition;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.core.type.AnnotatedTypeMetadata;

import java.util.Arrays;
import java.util.Objects;

public class OnProfileCondition implements Condition {

    @Override
    public boolean matches(ConditionContext context, AnnotatedTypeMetadata metadata) {
        Environment env = context.getEnvironment();

        EnvironmentProfile[] profiles = (EnvironmentProfile[]) Objects.requireNonNull(metadata
                                                                              .getAnnotationAttributes(ConditionalOnProfile.class.getName()))
                                                                      .get("value");

        Profiles activeProfiles = Profiles.of(Arrays.stream(profiles)
                                                    .map(EnvironmentProfile::getProfile)
                                                    .toArray(String[]::new)
        );

        return env.acceptsProfiles(activeProfiles);
    }
}
