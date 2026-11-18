package com.connect11.server.domain.auth.repository;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import org.springframework.dao.DataAccessException;
import org.springframework.data.redis.core.RedisOperations;
import org.springframework.data.redis.core.SessionCallback;
import org.springframework.data.redis.core.StringRedisTemplate;

final class RedisOps {

    private RedisOps() {
    }

    // TTL 없는 키가 남지 않게 묶음
    static void putAllWithTtl(StringRedisTemplate redis, String key, Map<String, String> fields, Duration ttl) {
        redis.execute(new SessionCallback<List<Object>>() {
            @Override
            @SuppressWarnings("unchecked")
            public <K, V> List<Object> execute(RedisOperations<K, V> operations) throws DataAccessException {
                RedisOperations<String, String> ops = (RedisOperations<String, String>) operations;
                ops.multi();
                ops.opsForHash().putAll(key, fields);
                ops.expire(key, ttl);
                return ops.exec();
            }
        });
    }
}