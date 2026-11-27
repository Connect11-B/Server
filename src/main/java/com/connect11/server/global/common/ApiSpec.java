package com.connect11.server.global.common;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;

@Getter
@RequiredArgsConstructor
public enum ApiSpec implements CustomResponseKind {

    EMAIL_SEND("POST", "/api/v1/auth/email/send", "이메일 인증 코드 발송", HttpStatus.OK),
    EMAIL_VERIFY("POST", "/api/v1/auth/email/verify", "이메일 인증 코드 검증", HttpStatus.OK),
    SIGNUP("POST", "/api/v1/auth/signup", "회원가입", HttpStatus.CREATED),
    AUTH_LOGIN("POST", "/api/v1/auth/login", "로그인", HttpStatus.OK),
    AUTH_REFRESH("POST", "/api/v1/auth/refresh", "토큰 재발급", HttpStatus.OK),
    LOGOUT("POST", "/api/v1/auth/logout", "로그아웃", HttpStatus.NO_CONTENT),
    PASSWORD_RESET("POST", "/api/v1/password/reset", "비밀번호 재설정", HttpStatus.OK),
    UNKNOWN(null, null, "알 수 없는 API", HttpStatus.OK);

    private final String method;
    private final String path;
    private final String name;
    private final HttpStatus httpStatus;

    @Override
    public String getFeatureCode() {
        return name();
    }

    public static CustomResponseKind find(String method, String uri) {
        for (ApiSpec spec : values()) {
            if (spec != UNKNOWN && spec.method.equalsIgnoreCase(method) && spec.path.equals(uri)) {
                return spec;
            }
        }
        return UNKNOWN;
    }
}
