package com.connect11.server.global.config;

import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

@ConfigurationProperties(prefix = "app")
public record AppProperties(Jwt jwt, Auth auth, Mail mail, Cors cors, Admin admin) {

    public record Jwt(String secret, @DefaultValue("1800") long accessTokenTtlSeconds) {
    }

    public record Auth(String codePepper,
                       @DefaultValue("1209600") long refreshTokenTtlSeconds,
                       @DefaultValue("true") boolean cookieSecure,
                       @DefaultValue("Strict") String cookieSameSite) {
    }

    public record Mail(@DefaultValue("smtp") String mode, String from) {
    }

    public record Cors(List<String> allowedOrigins) {
    }

    public record Admin(String email, String password, @DefaultValue("관리자") String name) {
    }
}
