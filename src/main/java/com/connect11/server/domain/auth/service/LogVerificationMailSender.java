package com.connect11.server.domain.auth.service;

import com.connect11.server.domain.auth.entity.VerificationPurpose;
import com.connect11.server.global.util.EmailNormalizer;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

/** 로컬·테스트 전용. 메일 대신 코드를 로그로 출력한다. prod에서는 MailModeGuard가 기동을 막는다. */
@Slf4j
@Component
@ConditionalOnProperty(prefix = "app.mail", name = "mode", havingValue = "log")
public class LogVerificationMailSender implements VerificationMailSender {

    @Override
    public void sendCode(String to, String code, VerificationPurpose purpose) {
        log.warn("[메일 log 모드 - 운영 사용 금지] purpose={} to={} code={}", purpose, EmailNormalizer.mask(to), code);
    }
}