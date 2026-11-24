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
public class LoginAttemptLimiter {

    private static final String PREFIX = "auth:login-attempt:";

    private static final RedisScript<Long> INCR_WITH_TTL = new DefaultRedisScript<>(
            "local c = redis.call('INCR', KEYS[1]) "
                    + "if c == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end "
                    + "return c", Long.class);

    private final StringRedisTemplate redis;

    public long increment(String key, Duration window) {
        Long count = redis.execute(INCR_WITH_TTL, List.of(PREFIX + key), String.valueOf(window.toSeconds()));
        return count == null ? Long.MAX_VALUE : count;
    }

    public void reset(String key) {
        redis.delete(PREFIX + key);
    }
}
