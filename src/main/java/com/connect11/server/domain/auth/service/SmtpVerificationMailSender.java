package com.connect11.server.domain.auth.service;

import com.connect11.server.domain.auth.entity.VerificationPurpose;
import com.connect11.server.global.config.AppProperties;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Component;

@Component
@ConditionalOnProperty(prefix = "app.mail", name = "mode", havingValue = "smtp", matchIfMissing = true)
public class SmtpVerificationMailSender implements VerificationMailSender {

    private final JavaMailSender mailSender;
    private final String from;

    public SmtpVerificationMailSender(JavaMailSender mailSender, AppProperties properties) {
        String from = properties.mail() == null ? null : properties.mail().from();
        if (from == null || from.isBlank()) {
            throw new IllegalStateException("smtp 모드에서는 MAIL_FROM(app.mail.from)이 필요합니다.");
        }
        this.mailSender = mailSender;
        this.from = from;
    }

    @Override
    public void sendCode(String to, String code, VerificationPurpose purpose) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(from);
        message.setTo(to);
        message.setSubject(purpose == VerificationPurpose.SIGNUP
                ? "[빌리지] 회원가입 인증 코드"
                : "[빌리지] 비밀번호 재설정 인증 코드");
        message.setText("""
                인증 코드: %s

                10분 안에 입력해 주세요.
                본인이 요청하지 않았다면 이 메일을 무시하세요. 인증 코드는 누구에게도 알려주지 마세요.
                """.formatted(code));
        mailSender.send(message);
    }
}