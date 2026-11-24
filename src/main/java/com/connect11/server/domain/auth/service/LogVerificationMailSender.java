package com.connect11.server.domain.auth.service;

import com.connect11.server.domain.auth.entity.VerificationPurpose;
import com.connect11.server.global.util.EmailNormalizer;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@ConditionalOnProperty(prefix = "app.mail", name = "mode", havingValue = "log")
public class LogVerificationMailSender implements VerificationMailSender {

    @Override
    public void sendCode(String to, String code, VerificationPurpose purpose) {
        log.warn("[메일 log 모드 - 운영 사용 금지] purpose={} to={} code={}", purpose, EmailNormalizer.mask(to), code);
    }
}
