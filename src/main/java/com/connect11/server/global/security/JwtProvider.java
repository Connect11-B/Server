package com.connect11.server.global.security;

import com.connect11.server.domain.user.entity.Role;
import com.connect11.server.global.config.AppProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.Optional;
import javax.crypto.SecretKey;
import org.springframework.stereotype.Component;

@Component
public class JwtProvider {

    private static final String ISSUER = "village-server";
    private static final int MIN_SECRET_BYTES = 32;

    private final SecretKey key;
    private final long accessTokenTtlSeconds;

    public JwtProvider(AppProperties properties) {
        String secret = properties.jwt() == null ? null : properties.jwt().secret();
        byte[] secretBytes = secret == null ? new byte[0] : secret.getBytes(StandardCharsets.UTF_8);
        if (secretBytes.length < MIN_SECRET_BYTES) {
            throw new IllegalStateException("JWT_SECRET이 없거나 32바이트 미만입니다.");
        }
        this.key = Keys.hmacShaKeyFor(secretBytes);
        this.accessTokenTtlSeconds = properties.jwt().accessTokenTtlSeconds();
    }

    public long getAccessTokenTtlSeconds() {
        return accessTokenTtlSeconds;
    }

    public String createAccessToken(Long userId, Role role, String sessionId) {
        Instant now = Instant.now();
        return Jwts.builder()
                .issuer(ISSUER)
                .subject(String.valueOf(userId))
                .claim("role", role.name())
                .claim("sid", sessionId)
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(accessTokenTtlSeconds)))
                .signWith(key, Jwts.SIG.HS256)
                .compact();
    }

    public Optional<AuthUser> parse(String token) {
        try {
            Claims claims = Jwts.parser()
                    .verifyWith(key)
                    .requireIssuer(ISSUER)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

            String subject = claims.getSubject();
            String role = claims.get("role", String.class);
            String sid = claims.get("sid", String.class);
            if (subject == null || role == null || sid == null || claims.getExpiration() == null) {
                return Optional.empty();
            }
            return Optional.of(new AuthUser(Long.valueOf(subject), Role.valueOf(role), sid));
        } catch (JwtException | IllegalArgumentException e) {//잘못된 숫자 subject, 알 수 없는 role, 빈 토큰 등
            return Optional.empty();
        }
    }
}