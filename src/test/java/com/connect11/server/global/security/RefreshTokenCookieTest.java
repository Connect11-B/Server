package com.connect11.server.global.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.connect11.server.global.config.AppProperties;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseCookie;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.mock.web.MockHttpServletRequest;

class RefreshTokenCookieTest {

    private static AppProperties props(boolean secure, String sameSite) {
        return new AppProperties(null, new AppProperties.Auth("p", 1209600, secure, sameSite), null, null, null);
    }

    @Test
    void 발급_쿠키는_HttpOnly_Secure_SameSite_그리고_인증_경로로_제한된다() {
        ResponseCookie cookie = new RefreshTokenCookie(props(true, "Strict"), new MockEnvironment()).issue("sid.secret");

        assertThat(cookie.getName()).isEqualTo("refresh_token");
        assertThat(cookie.getValue()).isEqualTo("sid.secret");
        assertThat(cookie.isHttpOnly()).isTrue();
        assertThat(cookie.isSecure()).isTrue();
        assertThat(cookie.getSameSite()).isEqualTo("Strict");
        assertThat(cookie.getPath()).isEqualTo("/api/v1/auth");
        assertThat(cookie.getMaxAge().getSeconds()).isEqualTo(1209600);
        assertThat(cookie.getDomain()).isNull();
    }

    @Test
    void 삭제_쿠키는_같은_속성에_Max_Age_0() {
        ResponseCookie cookie = new RefreshTokenCookie(props(true, "Strict"), new MockEnvironment()).clear();

        assertThat(cookie.getValue()).isEmpty();
        assertThat(cookie.getMaxAge().getSeconds()).isZero();
        assertThat(cookie.getPath()).isEqualTo("/api/v1/auth");
        assertThat(cookie.isHttpOnly()).isTrue();
        assertThat(cookie.isSecure()).isTrue();
    }

    @Test
    void 요청에서_쿠키를_읽는다() {
        RefreshTokenCookie factory = new RefreshTokenCookie(props(true, "Strict"), new MockEnvironment());
        MockHttpServletRequest withCookie = new MockHttpServletRequest();
        withCookie.setCookies(new Cookie("other", "x"), new Cookie("refresh_token", "sid.secret"));
        MockHttpServletRequest empty = new MockHttpServletRequest();
        MockHttpServletRequest blank = new MockHttpServletRequest();
        blank.setCookies(new Cookie("refresh_token", " "));

        assertThat(factory.read(withCookie)).contains("sid.secret");
        assertThat(factory.read(empty)).isEmpty();
        assertThat(factory.read(blank)).isEmpty();
    }

    @Test
    void 허용되지_않는_SameSite_값은_시작을_실패시킨다() {
        assertThatThrownBy(() -> new RefreshTokenCookie(props(true, "none-ish"), new MockEnvironment()))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void SameSite_None은_Secure가_필수() {
        assertThatThrownBy(() -> new RefreshTokenCookie(props(false, "None"), new MockEnvironment()))
                .isInstanceOf(IllegalStateException.class);
        assertThat(new RefreshTokenCookie(props(true, "None"), new MockEnvironment()).issue("a.b").getSameSite())
                .isEqualTo("None");
    }

    @Test
    void 운영_프로파일에서는_Secure를_끌_수_없다() {
        MockEnvironment prod = new MockEnvironment();
        prod.setActiveProfiles("prod");

        assertThatThrownBy(() -> new RefreshTokenCookie(props(false, "Strict"), prod))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Secure");
    }

    @Test
    void 프로필을_지정하지_않으면_Secure를_끌_수_없다() {
        assertThatThrownBy(() -> new RefreshTokenCookie(props(false, "Strict"), new MockEnvironment()))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Secure");
    }

    @Test
    void local_프로필을_명시하면_Secure를_끌_수_있다() {
        MockEnvironment local = new MockEnvironment();
        local.setActiveProfiles("local");

        assertThat(new RefreshTokenCookie(props(false, "Strict"), local).issue("a.b").isSecure()).isFalse();
    }
}
