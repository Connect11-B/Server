package com.connect11.server.global.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.connect11.server.global.config.AppProperties;
import org.junit.jupiter.api.Test;

class SecretHasherTest {

    private static final String PEPPER = "test-only-pepper-not-for-production";

    @Test
    void pepper가_없거나_32바이트_미만이면_기동_실패() {
        assertThatThrownBy(() -> new SecretHasher(props(null))).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> new SecretHasher(props("short-pepper"))).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void 같은_코드라도_인증ID가_다르면_해시가_다르다() {
        SecretHasher hasher = new SecretHasher(props(PEPPER));

        assertThat(hasher.codeHash("id-1", "123456")).isNotEqualTo(hasher.codeHash("id-2", "123456"));
        assertThat(hasher.codeHash("id-1", "123456")).isEqualTo(hasher.codeHash("id-1", "123456"));
    }

    @Test
    void pepper가_다르면_해시가_다르다() {
        SecretHasher a = new SecretHasher(props(PEPPER));
        SecretHasher b = new SecretHasher(props(PEPPER + "-other"));

        assertThat(a.emailHash("a@school.kr")).isNotEqualTo(b.emailHash("a@school.kr"));
    }

    @Test
    void 해시에_원문이_드러나지_않는다() {
        SecretHasher hasher = new SecretHasher(props(PEPPER));

        assertThat(hasher.emailHash("student@school.kr")).doesNotContain("student").hasSize(64);
        assertThat(SecretHasher.sha256("token-value")).doesNotContain("token").hasSize(64);
    }

    @Test
    void 상수시간_비교() {
        assertThat(SecretHasher.constantTimeEquals("abc", "abc")).isTrue();
        assertThat(SecretHasher.constantTimeEquals("abc", "abd")).isFalse();
        assertThat(SecretHasher.constantTimeEquals(null, "abc")).isFalse();
    }

    private static AppProperties props(String pepper) {
        return new AppProperties(null, new AppProperties.Auth(pepper, 1209600), null, null);
    }
}
