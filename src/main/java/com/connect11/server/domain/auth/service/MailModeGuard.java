package com.connect11.server.domain.auth.service;

import com.connect11.server.global.config.AppProperties;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.stereotype.Component;

/** 잘못된 메일 설정으로 운영 서버가 뜨지 않게 기동 시점에 검사한다. */
@Component
public class MailModeGuard {

    public MailModeGuard(AppProperties properties, Environment environment) {
        String mode = properties.mail() == null ? "smtp" : properties.mail().mode();
        if (!"log".equals(mode) && !"smtp".equals(mode)) {
            throw new IllegalStateException("app.mail.mode는 log 또는 smtp만 가능합니다: " + mode);
        }
        if ("log".equals(mode) && environment.acceptsProfiles(Profiles.of("prod"))) {
            throw new IllegalStateException("prod 프로필에서는 app.mail.mode=log를 사용할 수 없습니다.");
        }
    }
}