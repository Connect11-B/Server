package com.connect11.server.global.response;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum ApiSpec {

    EMAIL_SEND("POST", "/api/v1/auth/email/send", "이메일 인증 코드 발송"),
    EMAIL_VERIFY("POST", "/api/v1/auth/email/verify", "이메일 인증 코드 검증"),
    SIGNUP("POST", "/api/v1/auth/signup", "회원가입"),
    AUTH_LOGIN("POST", "/api/v1/auth/login", "로그인"),
    AUTH_REFRESH("POST", "/api/v1/auth/refresh", "토큰 재발급"),
    LOGOUT("POST", "/api/v1/auth/logout", "로그아웃"),
    PASSWORD_RESET("POST", "/api/v1/password/reset", "비밀번호 재설정");

    private final String method;
    private final String path;
    private final String name;

    public static ApiInfo find(String method, String uri) {
        for (ApiSpec spec : values()) {
            if (spec.method.equalsIgnoreCase(method) && spec.path.equals(uri)) {
                return ApiInfo.of(spec);
            }
        }
        return ApiInfo.unknown();
    }
}

//어떤 API에서 난 에러인지 표시