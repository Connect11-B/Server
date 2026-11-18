package com.connect11.server.domain.auth.repository;

import java.time.Duration;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.data.redis.core.script.RedisScript;
import org.springframework.stereotype.Repository;

/** 이메일 발송 제한. 키에는 이메일 원문 대신 HMAC 값(emailKey)을 쓴다. */
@Repository
@RequiredArgsConstructor
public class EmailSendRateLimiter {

    private static final String COOLDOWN_PREFIX = "auth:ev-cooldown:";
    private static final String HOURLY_PREFIX = "auth:ev-hourly:";

    // INCR과 첫 EXPIRE를 원자적으로 처리 (TTL 없는 카운터가 남아 영구 차단되는 것 방지)
    private static final RedisScript<Long> INCR_WITH_TTL = new DefaultRedisScript<>(
            "local c = redis.call('INCR', KEYS[1]) "
                    + "if c == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end "
                    + "return c", Long.class);

    private final StringRedisTemplate redis;

    /** 재발송 대기 시간 확보. 이미 대기 중이면 false. */
    public boolean tryAcquireCooldown(String emailKey, Duration cooldown) {
        return Boolean.TRUE.equals(redis.opsForValue().setIfAbsent(COOLDOWN_PREFIX + emailKey, "1", cooldown));
    }

    public void releaseCooldown(String emailKey) {
        redis.delete(COOLDOWN_PREFIX + emailKey);
    }

    /** 시간당 발송 횟수를 1 올리고 올린 값을 돌려준다. */
    public long incrementHourly(String emailKey, Duration window) {
        Long count = redis.execute(INCR_WITH_TTL, List.of(HOURLY_PREFIX + emailKey),
                String.valueOf(window.toSeconds()));
        return count == null ? Long.MAX_VALUE : count;
    }
}

//나중에 다시 볼것