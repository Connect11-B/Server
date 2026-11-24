package com.connect11.server.domain.auth.repository;

import java.time.Duration;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.data.redis.core.script.RedisScript;
import org.springframework.stereotype.Repository;

@Repository
@RequiredArgsConstructor
public class EmailSendRateLimiter {

    private static final String COOLDOWN_PREFIX = "auth:ev-cooldown:";
    private static final String HOURLY_PREFIX = "auth:ev-hourly:";

    private static final RedisScript<Long> INCR_WITH_TTL = new DefaultRedisScript<>(
            "local c = redis.call('INCR', KEYS[1]) "
                    + "if c == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end "
                    + "return c", Long.class);

    private final StringRedisTemplate redis;

    public boolean tryAcquireCooldown(String emailKey, Duration cooldown) {
        return Boolean.TRUE.equals(redis.opsForValue().setIfAbsent(COOLDOWN_PREFIX + emailKey, "1", cooldown));
    }

    public void releaseCooldown(String emailKey) {
        redis.delete(COOLDOWN_PREFIX + emailKey);
    }

    public long incrementHourly(String emailKey, Duration window) {
        Long count = redis.execute(INCR_WITH_TTL, List.of(HOURLY_PREFIX + emailKey),
                String.valueOf(window.toSeconds()));
        return count == null ? Long.MAX_VALUE : count;
    }
}
