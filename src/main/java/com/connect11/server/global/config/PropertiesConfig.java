package com.connect11.server.global.config;

import java.util.Arrays;
import java.util.Set;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;

@Configuration
@EnableConfigurationProperties(AppProperties.class)
public class PropertiesConfig {

    private static final Set<String> DEV_PROFILES = Set.of("local", "test");

    public PropertiesConfig(AppProperties properties, Environment environment) {
        validateMailMode(properties.mail(), environment);
    }

    public static boolean isDevProfileActive(Environment environment) {
        String[] active = environment.getActiveProfiles();
        return active.length > 0
                && Arrays.stream(active).anyMatch(DEV_PROFILES::contains)
                && Arrays.stream(active).noneMatch("prod"::equals);
    }

    static void validateMailMode(AppProperties.Mail mail, Environment environment) {
        if (mail != null && "log".equals(mail.mode()) && !isDevProfileActive(environment)) {
            throw new IllegalStateException(
                    "app.mail.mode=log는 local 또는 test 프로필을 명시적으로 활성화했을 때만 사용할 수 있습니다.");
        }
    }
}
