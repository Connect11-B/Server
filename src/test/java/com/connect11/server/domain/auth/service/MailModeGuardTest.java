package com.connect11.server.domain.auth.service;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.connect11.server.global.config.AppProperties;
import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;

class MailModeGuardTest {

    @Test
    void prod_프로필에서_log_모드면_기동_실패() {
        MockEnvironment env = new MockEnvironment();
        env.setActiveProfiles("prod");

        assertThatThrownBy(() -> new MailModeGuard(props("log"), env))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void prod_프로필에서_smtp_모드는_통과() {
        MockEnvironment env = new MockEnvironment();
        env.setActiveProfiles("prod");

        assertThatCode(() -> new MailModeGuard(props("smtp"), env)).doesNotThrowAnyException();
    }

    @Test
    void local_프로필에서_log_모드는_통과() {
        MockEnvironment env = new MockEnvironment();
        env.setActiveProfiles("local");

        assertThatCode(() -> new MailModeGuard(props("log"), env)).doesNotThrowAnyException();
    }

    @Test
    void 알_수_없는_모드는_기동_실패() {
        assertThatThrownBy(() -> new MailModeGuard(props("console"), new MockEnvironment()))
                .isInstanceOf(IllegalStateException.class);
    }

    private static AppProperties props(String mode) {
        return new AppProperties(null, null, new AppProperties.Mail(mode, null), null);
    }
}
