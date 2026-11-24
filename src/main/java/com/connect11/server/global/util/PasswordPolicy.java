package com.connect11.server.global.util;

import java.nio.charset.StandardCharsets;

/** 가입·비밀번호 재설정 공통 정책: 10~72자, 영문자와 숫자 포함. (로그인에서는 재검사하지 않는다) */
public final class PasswordPolicy {

    public static final int MIN_LENGTH = 10;
    public static final int MAX_LENGTH = 72;

    private PasswordPolicy() {
    }

    public static boolean isValid(String password) {
        if (password == null) {
            return false;
        }
        if (password.length() < MIN_LENGTH || password.length() > MAX_LENGTH) {
            return false;
        }
        // BCrypt는 72바이트까지만 반영한다. 멀티바이트 문자로 이를 넘으면 거부한다.
        if (password.getBytes(StandardCharsets.UTF_8).length > MAX_LENGTH) {
            return false;
        }
        boolean letter = false;
        boolean digit = false;
        for (int i = 0; i < password.length(); i++) {
            char c = password.charAt(i);
            if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
                letter = true;
            } else if (c >= '0' && c <= '9') {
                digit = true;
            }
        }
        return letter && digit;
    }
}
