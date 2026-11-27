package com.connect11.server.global.security;

import com.connect11.server.global.config.AppProperties;
import com.connect11.server.global.config.PropertiesConfig;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Duration;
import java.util.Optional;
import java.util.Set;
import org.springframework.core.env.Environment;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

@Component
public class RefreshTokenCookie {

    public static final String NAME = "refresh_token";
    static final String PATH = "/api/v1/auth";
    private static final Set<String> SAME_SITE_VALUES = Set.of("Strict", "Lax", "None");

    private final boolean secure;
    private final String sameSite;
    private final Duration maxAge;

    public RefreshTokenCookie(AppProperties properties, Environment environment) {
        AppProperties.Auth auth = properties.auth();
        this.secure = auth.cookieSecure();
        this.sameSite = auth.cookieSameSite();
        this.maxAge = Duration.ofSeconds(auth.refreshTokenTtlSeconds());

        if (!SAME_SITE_VALUES.contains(sameSite)) {
            throw new IllegalStateException("COOKIE_SAME_SITE는 Strict, Lax, None 중 하나여야 합니다.");
        }
        if ("None".equals(sameSite) && !secure) {
            throw new IllegalStateException("SameSite=None 쿠키는 Secure가 필수입니다.");
        }
        if (!secure && !PropertiesConfig.isDevProfileActive(environment)) {
            throw new IllegalStateException(
                    "refresh token 쿠키의 Secure는 local 또는 test 프로필을 명시적으로 활성화했을 때만 끌 수 있습니다.");
        }
    }

    public ResponseCookie issue(String refreshToken) {
        return base(refreshToken).maxAge(maxAge).build();
    }

    public ResponseCookie clear() {
        return base("").maxAge(Duration.ZERO).build();
    }

    public Optional<String> read(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return Optional.empty();
        }
        for (Cookie cookie : cookies) {
            if (NAME.equals(cookie.getName()) && cookie.getValue() != null && !cookie.getValue().isBlank()) {
                return Optional.of(cookie.getValue());
            }
        }
        return Optional.empty();
    }

    private ResponseCookie.ResponseCookieBuilder base(String value) {
        return ResponseCookie.from(NAME, value)
                .httpOnly(true)
                .secure(secure)
                .sameSite(sameSite)
                .path(PATH);
    }
}
