package com.connect11.server.domain.auth.repository;

import com.connect11.server.global.security.SecretHasher;
import com.connect11.server.global.util.SecureRandoms;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.data.redis.core.script.RedisScript;
import org.springframework.stereotype.Repository;

@Repository
@RequiredArgsConstructor
public class RefreshSessionStore {

    private static final String SESSION_PREFIX = "auth:rs:";
    private static final String USER_PREFIX = "auth:rs-user:";
    private static final String USED_PREFIX = "auth:rs-used:";
    private static final int MAX_USED_TOKENS = 1000;
    private static final Duration EXPIRED_GRACE = Duration.ofHours(1);
    private static final int MAX_TOKEN_LENGTH = 200;

    public enum Status { OK, INVALID, EXPIRED, REVOKED, REUSED }

    public record Issued(String sessionId, String refreshToken) {
    }

    public record RotateResult(Status status, Long userId, String sessionId, String refreshToken) {

        static RotateResult failure(Status status) {
            return new RotateResult(status, null, null, null);
        }
    }

    private record ParsedToken(String sessionId, String token) {
    }

    private static final RedisScript<Long> CREATE = new DefaultRedisScript<>(
            "redis.call('HSET', KEYS[1], 'userId', ARGV[1], 'cur', ARGV[2], 'expiresAt', ARGV[3]) "
                    + "redis.call('EXPIRE', KEYS[1], ARGV[4]) "
                    + "redis.call('SADD', KEYS[2], ARGV[5]) "
                    + "redis.call('EXPIRE', KEYS[2], ARGV[4]) "
                    + "return 1", Long.class);

    @SuppressWarnings({"rawtypes", "unchecked"})
    private static final RedisScript<List> ROTATE = new DefaultRedisScript<>(
            "local k = KEYS[1] "
                    + "local used = KEYS[2] "
                    + "if redis.call('EXISTS', k) == 0 then return {0} end "
                    + "local presented = ARGV[1] "
                    + "local cur = redis.call('HGET', k, 'cur') "
                    + "local isCur = (presented == cur) "
                    + "local isUsed = (not isCur) and redis.call('ZSCORE', used, presented) "
                    + "if (not isCur) and (not isUsed) then return {0} end "
                    + "if redis.call('HEXISTS', k, 'revoked') == 1 then return {2} end "
                    + "local userId = redis.call('HGET', k, 'userId') "
                    + "if tonumber(ARGV[3]) >= tonumber(redis.call('HGET', k, 'expiresAt')) then return {3} end "
                    + "if isUsed then redis.call('HSET', k, 'revoked', '1') return {4, userId} end "
                    + "redis.call('HSET', k, 'cur', ARGV[2], 'expiresAt', ARGV[4]) "
                    + "redis.call('ZADD', used, ARGV[3], cur) "
                    + "redis.call('ZREMRANGEBYSCORE', used, '-inf', '(' .. ARGV[7]) "
                    + "redis.call('ZREMRANGEBYRANK', used, 0, -(tonumber(ARGV[8]) + 1)) "
                    + "redis.call('EXPIRE', k, ARGV[5]) "
                    + "redis.call('EXPIRE', used, ARGV[5]) "
                    + "redis.call('EXPIRE', ARGV[6] .. userId, ARGV[5]) "
                    + "return {1, userId}", List.class);

    private static final RedisScript<Long> REVOKE_OWNED = new DefaultRedisScript<>(
            "local k = KEYS[1] "
                    + "if redis.call('EXISTS', k) == 0 then return 0 end "
                    + "if redis.call('HGET', k, 'userId') ~= ARGV[2] then return 0 end "
                    + "local cur = redis.call('HGET', k, 'cur') "
                    + "if ARGV[1] ~= cur and not redis.call('ZSCORE', KEYS[2], ARGV[1]) then return 0 end "
                    + "redis.call('HSET', k, 'revoked', '1') "
                    + "return 1", Long.class);

    private static final RedisScript<Long> REVOKE_SESSION_OWNED = new DefaultRedisScript<>(
            "local k = KEYS[1] "
                    + "if redis.call('EXISTS', k) == 0 then return 0 end "
                    + "if redis.call('HGET', k, 'userId') ~= ARGV[1] then return 0 end "
                    + "redis.call('HSET', k, 'revoked', '1') "
                    + "return 1", Long.class);

    @SuppressWarnings({"rawtypes", "unchecked"})
    private static final RedisScript<List> SESSION_STATE = new DefaultRedisScript<>(
            "return redis.call('HMGET', KEYS[1], 'userId', 'expiresAt', 'revoked')", List.class);

    private static final RedisScript<Long> REVOKE_MANY = new DefaultRedisScript<>(
            "for i = 2, #ARGV do "
                    + "local k = ARGV[1] .. ARGV[i] "
                    + "if redis.call('EXISTS', k) == 1 then redis.call('HSET', k, 'revoked', '1') end "
                    + "end return 1", Long.class);

    private final StringRedisTemplate redis;
    private final Clock clock;

    public Issued create(Long userId, Duration lifetime) {
        String sessionId = SecureRandoms.opaqueToken();
        String token = sessionId + "." + SecureRandoms.opaqueToken();
        long now = clock.instant().getEpochSecond();
        redis.execute(CREATE,
                List.of(sessionKey(sessionId), USER_PREFIX + userId),
                String.valueOf(userId),
                SecretHasher.sha256(token),
                String.valueOf(now + lifetime.toSeconds()),
                String.valueOf(lifetime.plus(EXPIRED_GRACE).toSeconds()),
                sessionId);
        return new Issued(sessionId, token);
    }

    public RotateResult rotate(String refreshToken, Duration lifetime) {
        Optional<ParsedToken> parsed = parse(refreshToken);
        if (parsed.isEmpty()) {
            return RotateResult.failure(Status.INVALID);
        }
        String sessionId = parsed.get().sessionId();
        String newToken = sessionId + "." + SecureRandoms.opaqueToken();
        long now = clock.instant().getEpochSecond();

        List<?> result = redis.execute(ROTATE,
                List.of(sessionKey(sessionId), USED_PREFIX + sessionId),
                SecretHasher.sha256(parsed.get().token()),
                SecretHasher.sha256(newToken),
                String.valueOf(now),
                String.valueOf(now + lifetime.toSeconds()),
                String.valueOf(lifetime.plus(EXPIRED_GRACE).toSeconds()),
                USER_PREFIX,
                String.valueOf(now - lifetime.toSeconds()),
                String.valueOf(MAX_USED_TOKENS));
        if (result == null || result.isEmpty()) {
            return RotateResult.failure(Status.INVALID);
        }
        long code = ((Number) result.get(0)).longValue();
        return switch ((int) code) {
            case 1 -> new RotateResult(Status.OK, Long.valueOf(String.valueOf(result.get(1))), sessionId, newToken);
            case 2 -> RotateResult.failure(Status.REVOKED);
            case 3 -> RotateResult.failure(Status.EXPIRED);
            case 4 -> new RotateResult(Status.REUSED, Long.valueOf(String.valueOf(result.get(1))), sessionId, null);
            default -> RotateResult.failure(Status.INVALID);
        };
    }

    public boolean revokeOwned(String refreshToken, Long ownerUserId) {
        Optional<ParsedToken> parsed = parse(refreshToken);
        if (parsed.isEmpty()) {
            return false;
        }
        Long ok = redis.execute(REVOKE_OWNED,
                List.of(sessionKey(parsed.get().sessionId()), USED_PREFIX + parsed.get().sessionId()),
                SecretHasher.sha256(parsed.get().token()),
                String.valueOf(ownerUserId));
        return Long.valueOf(1L).equals(ok);
    }

    public boolean isActive(String sessionId, Long userId) {
        if (sessionId == null || userId == null) {
            return false;
        }
        List<?> state = redis.execute(SESSION_STATE, List.of(sessionKey(sessionId)));
        if (state == null || state.size() < 3 || state.get(0) == null || state.get(1) == null) {
            return false;
        }
        if (!String.valueOf(userId).equals(String.valueOf(state.get(0))) || state.get(2) != null) {
            return false;
        }
        return clock.instant().getEpochSecond() < Long.parseLong(String.valueOf(state.get(1)));
    }

    public boolean revokeSessionOwned(String sessionId, Long ownerUserId) {
        Long ok = redis.execute(REVOKE_SESSION_OWNED, List.of(sessionKey(sessionId)), String.valueOf(ownerUserId));
        return Long.valueOf(1L).equals(ok);
    }

    public void revokeSession(String sessionId) {
        redis.execute(REVOKE_MANY, List.of(), SESSION_PREFIX, sessionId);
    }

    public void revokeAllForUser(Long userId) {
        String userKey = USER_PREFIX + userId;
        Set<String> sessionIds = redis.opsForSet().members(userKey);
        if (sessionIds != null && !sessionIds.isEmpty()) {
            Object[] args = new Object[sessionIds.size() + 1];
            args[0] = SESSION_PREFIX;
            int i = 1;
            for (String sid : sessionIds) {
                args[i++] = sid;
            }
            redis.execute(REVOKE_MANY, List.of(), args);
        }
        redis.delete(userKey);
    }

    public static Optional<String> sessionIdOf(String refreshToken) {
        return parse(refreshToken).map(ParsedToken::sessionId);
    }

    private static Optional<ParsedToken> parse(String token) {
        if (token == null || token.length() > MAX_TOKEN_LENGTH) {
            return Optional.empty();
        }
        int dot = token.indexOf('.');
        if (dot <= 0 || dot == token.length() - 1 || token.indexOf('.', dot + 1) >= 0) {
            return Optional.empty();
        }
        return Optional.of(new ParsedToken(token.substring(0, dot), token));
    }

    private static String sessionKey(String sessionId) {
        return SESSION_PREFIX + sessionId;
    }
}
