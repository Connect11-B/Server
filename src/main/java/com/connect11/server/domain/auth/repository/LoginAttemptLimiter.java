package com.connect11.server.domain.auth.repository;

import java.time.Duration;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.data.redis.core.script.RedisScript;
import org.springframework.stereotype.Repository;

/** 로그인 시도 제한. 키에는 이메일·IP 원문 대신 HMAC 값을 쓴다. */
@Repository
@RequiredArgsConstructor
public class LoginAttemptLimiter {

    private static final String PREFIX = "auth:login-attempt:";

    // INCR과 첫 EXPIRE를 원자적으로 처리 (TTL 없는 카운터가 남아 영구 차단되는 것 방지)
    private static final RedisScript<Long> INCR_WITH_TTL = new DefaultRedisScript<>(
            "local c = redis.call('INCR', KEYS[1]) "
                    + "if c == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end "
                    + "return c", Long.class);

    private final StringRedisTemplate redis;

    /** 시도 횟수를 먼저 1 올리고 올린 값을 돌려준다. (동시에 여러 번 시도해도 제한을 넘길 수 없다) */
    public long increment(String key, Duration window) {
        Long count = redis.execute(INCR_WITH_TTL, List.of(PREFIX + key), String.valueOf(window.toSeconds()));
        return count == null ? Long.MAX_VALUE : count;
    }

    /** 로그인에 성공하면 카운터를 지운다. */
    public void reset(String key) {
        redis.delete(PREFIX + key);
    }
}
