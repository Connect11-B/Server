package com.connect11.server.global.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.mock.env.MockEnvironment;

class PropertiesConfigTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withUserConfiguration(PropertiesConfig.class);

    @Test
    void prod_프로필에서_log_모드면_기동_실패() {
        MockEnvironment env = new MockEnvironment();
        env.setActiveProfiles("prod");

        assertThatThrownBy(() -> PropertiesConfig.validateMailMode(mail("log"), env))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void prod_프로필에서_smtp_모드는_통과() {
        MockEnvironment env = new MockEnvironment();
        env.setActiveProfiles("prod");

        assertThatCode(() -> PropertiesConfig.validateMailMode(mail("smtp"), env)).doesNotThrowAnyException();
    }

    @Test
    void local_프로필에서_log_모드는_통과() {
        MockEnvironment env = new MockEnvironment();
        env.setActiveProfiles("local");

        assertThatCode(() -> PropertiesConfig.validateMailMode(mail("log"), env)).doesNotThrowAnyException();
    }

    @Test
    void 알_수_없는_모드는_기동_실패() {
        runner.withPropertyValues("app.mail.mode=console")
                .run(context -> assertThat(context).hasFailed());
    }

    @Test
    void 허용된_모드는_기동_성공() {
        runner.withPropertyValues("app.mail.mode=log")
                .run(context -> assertThat(context).hasNotFailed());
    }

    private static AppProperties.Mail mail(String mode) {
        return new AppProperties.Mail(mode, null);
    }
}
