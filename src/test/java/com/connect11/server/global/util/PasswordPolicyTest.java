package com.connect11.server.global.util;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class PasswordPolicyTest {

    @Test
    void 영문자와_숫자를_포함한_10자_이상이면_통과() {
        assertThat(PasswordPolicy.isValid("Example123!")).isTrue();
        assertThat(PasswordPolicy.isValid("abcdefghi1")).isTrue();
    }

    @Test
    void 길이_경계값() {
        assertThat(PasswordPolicy.isValid("abcdefgh1")).isFalse();               // 9자
        assertThat(PasswordPolicy.isValid("abcdefghi1")).isTrue();               // 10자
        assertThat(PasswordPolicy.isValid("a1".repeat(36))).isTrue();            // 72자
        assertThat(PasswordPolicy.isValid("a1".repeat(36) + "a")).isFalse();     // 73자
    }

    @Test
    void 영문자나_숫자가_없으면_거부() {
        assertThat(PasswordPolicy.isValid("abcdefghijk")).isFalse();
        assertThat(PasswordPolicy.isValid("12345678901")).isFalse();
        assertThat(PasswordPolicy.isValid("!!!!!!!!!!!!")).isFalse();
    }

    @Test
    void 한글만으로는_영문자로_인정하지_않는다() {
        assertThat(PasswordPolicy.isValid("가나다라마바사아자차1")).isFalse();
    }

    @Test
    void 글자_수는_72자_이하여도_UTF8_72바이트를_넘으면_거부() {
        String password = "가".repeat(30) + "a1";   // 32자지만 92바이트
        assertThat(password.length()).isLessThanOrEqualTo(72);
        assertThat(PasswordPolicy.isValid(password)).isFalse();
    }

    @Test
    void null은_거부() {
        assertThat(PasswordPolicy.isValid(null)).isFalse();
    }
}
