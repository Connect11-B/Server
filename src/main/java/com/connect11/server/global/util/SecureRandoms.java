package com.connect11.server.global.util;

import java.security.SecureRandom;
import java.util.Base64;

public final class SecureRandoms {

    private static final SecureRandom RANDOM = new SecureRandom();

    private SecureRandoms() {
    }

    public static String sixCode() {
        return String.format("%06d", RANDOM.nextInt(1_000_000));
    }

    public static String opaqueToken() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
