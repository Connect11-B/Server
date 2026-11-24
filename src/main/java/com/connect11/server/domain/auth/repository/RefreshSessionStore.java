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

/**
 * 로그인 세션(refresh session) 저장소.
 *
 * <p>refresh token은 "{sessionId}.{secret}" 형태의 불투명 문자열이며, Redis에는 전체 토큰의 SHA-256 해시만 저장한다.
 * 회전 시 직전 토큰의 해시(prev)를 남겨 두었다가 다시 제출되면 재사용으로 보고 세션을 폐기한다.
 * 확인·회전·폐기는 모두 Lua 스크립트 한 번으로 원자적으로 처리한다.
 * 만료 후에도 키를 잠시(EXPIRED_GRACE) 남겨 EXPIRED와 INVALID를 구분한다.
 */
@Repository
@RequiredArgsConstructor
public class RefreshSessionStore {

    private static final String SESSION_PREFIX = "auth:rs:";
    private static final String USER_PREFIX = "auth:rs-user:";
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

    // KEYS: 세션 키, 사용자 세션 집합 / ARGV: userId, 토큰 해시, 만료 시각, TTL(초), sessionId
    private static final RedisScript<Long> CREATE = new DefaultRedisScript<>(
            "redis.call('HSET', KEYS[1], 'userId', ARGV[1], 'cur', ARGV[2], 'expiresAt', ARGV[3]) "
                    + "redis.call('EXPIRE', KEYS[1], ARGV[4]) "
                    + "redis.call('SADD', KEYS[2], ARGV[5]) "
                    + "redis.call('EXPIRE', KEYS[2], ARGV[4]) "
                    + "return 1", Long.class);

    // KEYS: 세션 키 / ARGV: 제출 해시, 새 해시, 현재 시각, 새 만료 시각, TTL(초), 사용자 세션 집합 접두어
    // 반환: {0 INVALID} {1 OK userId} {2 REVOKED} {3 EXPIRED} {4 REUSED userId}
    @SuppressWarnings({"rawtypes", "unchecked"})
    private static final RedisScript<List> ROTATE = new DefaultRedisScript<>(
            "local k = KEYS[1] "
                    + "if redis.call('EXISTS', k) == 0 then return {0} end "
                    + "local presented = ARGV[1] "
                    + "local cur = redis.call('HGET', k, 'cur') "
                    + "local prev = redis.call('HGET', k, 'prev') "
                    + "local isCur = (presented == cur) "
                    + "local isPrev = (prev and presented == prev) "
                    + "if (not isCur) and (not isPrev) then return {0} end "
                    + "if redis.call('HEXISTS', k, 'revoked') == 1 then return {2} end "
                    + "local userId = redis.call('HGET', k, 'userId') "
                    + "if tonumber(ARGV[3]) >= tonumber(redis.call('HGET', k, 'expiresAt')) then return {3} end "
                    + "if isPrev then redis.call('HSET', k, 'revoked', '1') return {4, userId} end "
                    + "redis.call('HSET', k, 'prev', cur, 'cur', ARGV[2], 'expiresAt', ARGV[4]) "
                    + "redis.call('EXPIRE', k, ARGV[5]) "
                    + "redis.call('EXPIRE', ARGV[6] .. userId, ARGV[5]) "
                    + "return {1, userId}", List.class);

    // KEYS: 세션 키 / ARGV: 제출 해시, 소유자 userId
    private static final RedisScript<Long> REVOKE_OWNED = new DefaultRedisScript<>(
            "local k = KEYS[1] "
                    + "if redis.call('EXISTS', k) == 0 then return 0 end "
                    + "if redis.call('HGET', k, 'userId') ~= ARGV[2] then return 0 end "
                    + "local cur = redis.call('HGET', k, 'cur') "
                    + "local prev = redis.call('HGET', k, 'prev') "
                    + "if ARGV[1] ~= cur and not (prev and ARGV[1] == prev) then return 0 end "
                    + "redis.call('HSET', k, 'revoked', '1') "
                    + "return 1", Long.class);

    // KEYS: 세션 키 / ARGV: 소유자 userId  (access token의 sid로 로그아웃할 때)
    private static final RedisScript<Long> REVOKE_SESSION_OWNED = new DefaultRedisScript<>(
            "local k = KEYS[1] "
                    + "if redis.call('EXISTS', k) == 0 then return 0 end "
                    + "if redis.call('HGET', k, 'userId') ~= ARGV[1] then return 0 end "
                    + "redis.call('HSET', k, 'revoked', '1') "
                    + "return 1", Long.class);

    // ARGV: 세션 키 접두어, sessionId...  (존재하는 세션만 폐기 표시. TTL은 그대로 유지)
    private static final RedisScript<Long> REVOKE_MANY = new DefaultRedisScript<>(
            "for i = 2, #ARGV do "
                    + "local k = ARGV[1] .. ARGV[i] "
                    + "if redis.call('EXISTS', k) == 1 then redis.call('HSET', k, 'revoked', '1') end "
                    + "end return 1", Long.class);

    private final StringRedisTemplate redis;
    private final Clock clock;

    /** 새 로그인 세션을 만들고 refresh token 원문을 돌려준다. */
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

    /** 제출된 토큰을 검증하고 새 토큰으로 회전한다. 이미 회전된 토큰이면 세션을 폐기한다. */
    public RotateResult rotate(String refreshToken, Duration lifetime) {
        Optional<ParsedToken> parsed = parse(refreshToken);
        if (parsed.isEmpty()) {
            return RotateResult.failure(Status.INVALID);
        }
        String sessionId = parsed.get().sessionId();
        String newToken = sessionId + "." + SecureRandoms.opaqueToken();
        long now = clock.instant().getEpochSecond();

        List<?> result = redis.execute(ROTATE,
                List.of(sessionKey(sessionId)),
                SecretHasher.sha256(parsed.get().token()),
                SecretHasher.sha256(newToken),
                String.valueOf(now),
                String.valueOf(now + lifetime.toSeconds()),
                String.valueOf(lifetime.plus(EXPIRED_GRACE).toSeconds()),
                USER_PREFIX);
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

    /**
     * 로그아웃. 토큰이 해당 사용자의 세션 토큰일 때만 폐기하고 true를 돌려준다.
     * 이미 폐기된 세션이어도 true이므로 로그아웃은 멱등이다.
     */
    public boolean revokeOwned(String refreshToken, Long ownerUserId) {
        Optional<ParsedToken> parsed = parse(refreshToken);
        if (parsed.isEmpty()) {
            return false;
        }
        Long ok = redis.execute(REVOKE_OWNED,
                List.of(sessionKey(parsed.get().sessionId())),
                SecretHasher.sha256(parsed.get().token()),
                String.valueOf(ownerUserId));
        return Long.valueOf(1L).equals(ok);
    }

    /** 쿠키가 없을 때의 로그아웃. 서명된 access token의 sid가 요청 사용자의 세션일 때만 폐기한다. */
    public boolean revokeSessionOwned(String sessionId, Long ownerUserId) {
        Long ok = redis.execute(REVOKE_SESSION_OWNED, List.of(sessionKey(sessionId)), String.valueOf(ownerUserId));
        return Long.valueOf(1L).equals(ok);
    }

    /** 세션 하나를 폐기한다. (비활성 계정 등 서버 측 사유) */
    public void revokeSession(String sessionId) {
        redis.execute(REVOKE_MANY, List.of(), SESSION_PREFIX, sessionId);
    }

    /** 사용자의 모든 세션을 폐기한다. (비밀번호 재설정) */
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
