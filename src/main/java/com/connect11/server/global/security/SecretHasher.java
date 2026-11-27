package com.connect11.server.global.security;

import com.connect11.server.global.config.AppProperties;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.stereotype.Component;

@Component
public class SecretHasher {

    private static final String HMAC_ALG = "HmacSHA256";
    private static final int MIN_PEPPER_BYTES = 32;

    private final SecretKeySpec key;

    public SecretHasher(AppProperties properties) {
        String pepper = properties.auth() == null ? null : properties.auth().codePepper();
        byte[] bytes = pepper == null ? new byte[0] : pepper.getBytes(StandardCharsets.UTF_8);
        if (bytes.length < MIN_PEPPER_BYTES) {
            throw new IllegalStateException("AUTH_CODE_PEPPER가 설정되지 않았거나 32바이트 미만입니다.");
        }
        this.key = new SecretKeySpec(bytes, HMAC_ALG);
    }

    public String hmac(String value) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALG);
            mac.init(key);
            return HexFormat.of().formatHex(mac.doFinal(value.getBytes(StandardCharsets.UTF_8)));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HMAC 계산 실패", e);
        }
    }

    public String codeHash(String verificationId, String code) {
        return hmac("code:" + verificationId + ":" + code);
    }

    public String emailHash(String normalizedEmail) {
        return hmac("email:" + normalizedEmail);
    }

    public static String sha256(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 미지원", e);
        }
    }

    public static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) {
            return false;
        }
        return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }
}
