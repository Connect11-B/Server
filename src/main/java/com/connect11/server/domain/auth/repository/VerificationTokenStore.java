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

@Repository
@RequiredArgsConstructor
public class VerificationTokenStore {

    private static final String KEY_PREFIX = "auth:vt:";

    private final StringRedisTemplate redis;

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

    public boolean markUsed(VerificationPurpose purpose, String token) {
        return Boolean.TRUE.equals(redis.opsForHash().putIfAbsent(key(purpose, token), "used", "1"));
    }

    private String key(VerificationPurpose purpose, String token) {
        return KEY_PREFIX + purpose.name() + ":" + SecretHasher.sha256(token);
    }
}
