package com.connect11.server.global.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;

@Configuration
@EnableConfigurationProperties(AppProperties.class)
public class PropertiesConfig {

    public PropertiesConfig(AppProperties properties, Environment environment) {
        validateMailMode(properties.mail(), environment);
    }

    static void validateMailMode(AppProperties.Mail mail, Environment environment) {
        if (mail != null && "log".equals(mail.mode()) && environment.acceptsProfiles(Profiles.of("prod"))) {
            throw new IllegalStateException("prod 프로필에서는 app.mail.mode=log를 사용할 수 없습니다.");
        }
    }
}
