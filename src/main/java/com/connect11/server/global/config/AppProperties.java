package com.connect11.server.global.config;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Pattern;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

@Validated
@ConfigurationProperties(prefix = "app")
public record AppProperties(Jwt jwt, Auth auth, @Valid Mail mail, Cors cors, Admin admin) {

    public record Jwt(String secret, @DefaultValue("1800") long accessTokenTtlSeconds) {
    }

    public record Auth(String codePepper,
                       @DefaultValue("1209600") long refreshTokenTtlSeconds,
                       @DefaultValue("true") boolean cookieSecure,
                       @DefaultValue("Strict") String cookieSameSite) {
    }

    public record Mail(
            @Pattern(regexp = "log|smtp", message = "app.mail.mode는 log 또는 smtp만 가능합니다.")
            @DefaultValue("smtp") String mode,
            String from) {
    }

    public record Cors(List<String> allowedOrigins) {
    }

    public record Admin(String email, String password, @DefaultValue("관리자") String name) {
    }
}
