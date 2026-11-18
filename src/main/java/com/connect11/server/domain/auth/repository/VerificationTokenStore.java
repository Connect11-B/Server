package com.connect11.server.domain.auth.repository;

import com.connect11.server.domain.auth.entity.VerificationPurpose;
import com.connect11.server.domain.auth.entity.VerificationToken;
import com.connect11.server.global.security.SecretHasher;
import com.connect11.server.global.util.SecureRandoms;
import java.time.Duration;
import java.util.Map;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Repository;

/**
 * signupToken / resetToken 저장소. 토큰 원문은 응답으로만 내보내고 Redis에는 SHA-256 해시만 저장한다.
 * 회원가입(4묶음)·비밀번호 재설정(5묶음)에서 find → 검증 → markUsed 순서로 사용한다.
 */
@Repository
@RequiredArgsConstructor
public class VerificationTokenStore {

    private static final String KEY_PREFIX = "auth:vt:";

    private final StringRedisTemplate redis;

    /** 토큰을 발급하고 원문을 돌려준다. */
    public String issue(VerificationPurpose purpose, String email, long expiresAtEpochSecond, Duration ttl) {
        String token = SecureRandoms.opaqueToken();
        RedisOps.putAllWithTtl(redis, key(purpose, token), Map.of(
                "email", email,
                "expiresAt", String.valueOf(expiresAtEpochSecond)), ttl);
        return token;
    }

    public Optional<VerificationToken> find(VerificationPurpose purpose, String token) {
        Map<Object, Object> m = redis.opsForHash().entries(key(purpose, token));
        if (m.isEmpty()) {
            return Optional.empty();
        }
        return Optional.of(new VerificationToken(
                purpose,
                (String) m.get("email"),
                Long.parseLong((String) m.get("expiresAt")),
                m.containsKey("used")));
    }

    /** 처음 사용 처리에 성공했을 때만 true. (HSETNX로 1회성 보장) */
    public boolean markUsed(VerificationPurpose purpose, String token) {
        return Boolean.TRUE.equals(redis.opsForHash().putIfAbsent(key(purpose, token), "used", "1"));
    }

    // 목적별로 키를 분리해 signupToken을 resetToken 자리에 쓰지 못하게 한다.
    private String key(VerificationPurpose purpose, String token) {
        return KEY_PREFIX + purpose.name() + ":" + SecretHasher.sha256(token);
    }
}

// 나중에 다시 확인