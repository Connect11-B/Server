package com.connect11.server.global.config;

import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

@ConfigurationProperties(prefix = "app")
public record AppProperties(Jwt jwt, Auth auth, Mail mail, Cors cors) {

    public record Jwt(String secret, @DefaultValue("1800") long accessTokenTtlSeconds) {
    }// 30분

    public record Auth(String codePepper, @DefaultValue("1209600") long refreshTokenTtlSeconds) {
    }// 14일

    public record Mail(@DefaultValue("log") String mode, String from) {
    }// 나중에 기본값 바꾸기

    public record Cors(List<String> allowedOrigins) {
    }
}