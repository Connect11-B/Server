package com.connect11.server.global.exception;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;

@Getter
@RequiredArgsConstructor
public enum ErrorCode {

    VALIDATION_ERROR(HttpStatus.BAD_REQUEST, "요청 값을 확인해 주세요."),
    PASSWORD_POLICY_VIOLATION(HttpStatus.BAD_REQUEST, "비밀번호 조건을 확인해 주세요."),

    UNAUTHENTICATED(HttpStatus.UNAUTHORIZED, "인증이 필요합니다."),
    AUTHENTICATION_FAILED(HttpStatus.UNAUTHORIZED, "아이디 또는 비밀번호가 올바르지 않습니다."),
    EMAIL_VERIFICATION_INVALID(HttpStatus.UNAUTHORIZED, "이메일 인증 정보가 유효하지 않습니다."),
    SIGNUP_TOKEN_INVALID(HttpStatus.UNAUTHORIZED, "회원가입 인증 정보가 유효하지 않습니다."),
    REFRESH_TOKEN_INVALID(HttpStatus.UNAUTHORIZED, "갱신 토큰이 유효하지 않습니다."),
    REFRESH_TOKEN_EXPIRED(HttpStatus.UNAUTHORIZED, "갱신 토큰이 만료되었습니다."),
    REFRESH_TOKEN_REVOKED(HttpStatus.UNAUTHORIZED, "갱신 토큰이 폐기되었습니다."),
    RESET_TOKEN_INVALID(HttpStatus.UNAUTHORIZED, "비밀번호 재설정 인증 정보가 유효하지 않습니다."),

    FORBIDDEN(HttpStatus.FORBIDDEN, "접근 권한이 없습니다."),
    ACCOUNT_INACTIVE(HttpStatus.FORBIDDEN, "사용할 수 없는 계정입니다."),

    EMAIL_ALREADY_REGISTERED(HttpStatus.CONFLICT, "이미 가입된 이메일입니다."),
    EMAIL_VERIFICATION_ALREADY_USED(HttpStatus.CONFLICT, "이메일 인증 정보는 이미 사용되었습니다."),
    SIGNUP_TOKEN_ALREADY_USED(HttpStatus.CONFLICT, "회원가입 인증 정보는 이미 사용되었습니다."),
    RESET_TOKEN_ALREADY_USED(HttpStatus.CONFLICT, "비밀번호 재설정 인증 정보는 이미 사용되었습니다."),

    EMAIL_VERIFICATION_EXPIRED(HttpStatus.GONE, "이메일 인증 코드가 만료되었습니다."),
    SIGNUP_TOKEN_EXPIRED(HttpStatus.GONE, "회원가입 인증 정보가 만료되었습니다."),
    RESET_TOKEN_EXPIRED(HttpStatus.GONE, "비밀번호 재설정 인증 정보가 만료되었습니다."),

    EMAIL_RATE_LIMITED(HttpStatus.TOO_MANY_REQUESTS, "잠시 후 다시 시도해 주세요."),
    EMAIL_VERIFICATION_ATTEMPTS_EXCEEDED(HttpStatus.TOO_MANY_REQUESTS, "인증 시도 횟수를 초과했습니다."),
    LOGIN_RATE_LIMITED(HttpStatus.TOO_MANY_REQUESTS, "요청이 너무 많습니다. 잠시 후 다시 시도해 주세요."),

    INTERNAL_ERROR(HttpStatus.INTERNAL_SERVER_ERROR, "서버 오류가 발생했습니다."),
    EMAIL_SEND_FAILED(HttpStatus.SERVICE_UNAVAILABLE, "인증 메일을 발송하지 못했습니다.");

    private final HttpStatus status;
    private final String message;
}