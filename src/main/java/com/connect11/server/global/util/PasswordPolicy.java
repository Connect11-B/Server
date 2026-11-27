package com.connect11.server.global.util;

import java.nio.charset.StandardCharsets;

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
