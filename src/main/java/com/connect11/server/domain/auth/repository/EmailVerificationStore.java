package com.connect11.server.domain.auth.repository;

import com.connect11.server.domain.auth.entity.EmailVerification;
import com.connect11.server.domain.auth.entity.VerificationPurpose;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.data.redis.core.script.RedisScript;
import org.springframework.stereotype.Repository;

@Repository
@RequiredArgsConstructor
public class EmailVerificationStore {

    private static final String KEY_PREFIX = "auth:ev:";
    private static final String LATEST_PREFIX = "auth:ev-latest:";

    // 키가 이미 사라졌으면 HINCRBY가 TTL 없는 새 키를 만들지 않도록 존재할 때만 증가
    private static final RedisScript<Long> INCREMENT_IF_EXISTS = new DefaultRedisScript<>(
            "if redis.call('EXISTS', KEYS[1]) == 1 then "
                    + "return redis.call('HINCRBY', KEYS[1], 'attempts', 1) "
                    + "end return -1", Long.class);

    // 같은 이메일·목적의 최신 인증 ID를 교체하고 이전 ID를 돌려준다.
    private static final RedisScript<String> REPLACE_LATEST = new DefaultRedisScript<>(
            "local old = redis.call('GET', KEYS[1]) "
                    + "redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[2]) "
                    + "return old", String.class);

    private final StringRedisTemplate redis;

    public void save(EmailVerification v, Duration ttl) {
        RedisOps.putAllWithTtl(redis, KEY_PREFIX + v.id(), Map.of(
                "email", v.email(),
                "purpose", v.purpose().name(),
                "codeHash", v.codeHash(),
                "expiresAt", String.valueOf(v.expiresAtEpochSecond()),
                "attempts", "0"), ttl);
    }

    public Optional<EmailVerification> find(String id) {
        Map<Object, Object> m = redis.opsForHash().entries(KEY_PREFIX + id);
        if (m.isEmpty()) {
            return Optional.empty();
        }
        return Optional.of(new EmailVerification(
                id,
                (String) m.get("email"),
                VerificationPurpose.valueOf((String) m.get("purpose")),
                (String) m.get("codeHash"),
                Long.parseLong((String) m.get("expiresAt")),
                m.containsKey("used")));
    }

    /** 시도 횟수를 1 올리고 올린 값을 돌려준다. 키가 없으면 -1. */
    public long incrementAttempts(String id) {
        Long result = redis.execute(INCREMENT_IF_EXISTS, List.of(KEY_PREFIX + id));
        return result == null ? -1 : result;
    }

    /** 처음 사용 처리에 성공했을 때만 true. 동시 요청 중 하나만 성공한다. (HSETNX) */
    public boolean markUsed(String id) {
        return Boolean.TRUE.equals(redis.opsForHash().putIfAbsent(KEY_PREFIX + id, "used", "1"));
    }

    public void delete(String id) {
        redis.delete(KEY_PREFIX + id);
    }

    /** 최신 인증 ID를 등록하고, 이전 인증 ID가 있으면 돌려준다. (재발송 시 이전 코드 무효화용) */
    public Optional<String> replaceLatest(String emailKey, VerificationPurpose purpose, String id, Duration ttl) {
        String old = redis.execute(REPLACE_LATEST,
                List.of(LATEST_PREFIX + purpose.name() + ":" + emailKey),
                id, String.valueOf(ttl.toSeconds()));
        return Optional.ofNullable(old).filter(o -> !o.equals(id));
    }
}



//이 부분 나중에 다시 공부