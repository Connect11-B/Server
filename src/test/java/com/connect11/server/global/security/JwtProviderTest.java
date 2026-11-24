package com.connect11.server.global.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.connect11.server.domain.user.entity.Role;
import com.connect11.server.global.config.AppProperties;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import org.junit.jupiter.api.Test;

class JwtProviderTest {

    private static final String SECRET = "test-only-jwt-secret-not-for-production-0123456789";

    @Test
    void 비밀값이_없거나_32바이트_미만이면_기동_실패() {
        assertThatThrownBy(() -> new JwtProvider(props(null, 1800))).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> new JwtProvider(props("too-short-secret", 1800)))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void 발급한_토큰을_파싱하면_사용자정보가_나온다() {
        JwtProvider provider = new JwtProvider(props(SECRET, 1800));

        String token = provider.createAccessToken(7L, Role.STUDENT, "session-1");

        assertThat(provider.parse(token)).contains(new AuthUser(7L, Role.STUDENT, "session-1"));
    }

    @Test
    void 다른_키로_서명된_토큰은_거부() {
        JwtProvider provider = new JwtProvider(props(SECRET, 1800));
        JwtProvider attacker = new JwtProvider(props(SECRET + "-attacker", 1800));

        String forged = attacker.createAccessToken(1L, Role.ADMIN, "s");

        assertThat(provider.parse(forged)).isEmpty();
    }

    @Test
    void 변조된_토큰은_거부() {
        JwtProvider provider = new JwtProvider(props(SECRET, 1800));
        String token = provider.createAccessToken(7L, Role.STUDENT, "s");
        String tampered = token.substring(0, token.length() - 2) + (token.endsWith("AA") ? "BB" : "AA");

        assertThat(provider.parse(tampered)).isEmpty();
    }

    @Test
    void 만료된_토큰은_거부() {
        JwtProvider provider = new JwtProvider(props(SECRET, -10));

        assertThat(provider.parse(provider.createAccessToken(7L, Role.STUDENT, "s"))).isEmpty();
    }

    @Test
    void 발급자가_다르거나_필수_claim이_없으면_거부() {
        JwtProvider provider = new JwtProvider(props(SECRET, 1800));
        var key = Keys.hmacShaKeyFor(SECRET.getBytes(StandardCharsets.UTF_8));
        Date exp = Date.from(Instant.now().plusSeconds(600));

        String otherIssuer = Jwts.builder().issuer("other-service").subject("1")
                .claim("role", "ADMIN").claim("sid", "s").expiration(exp).signWith(key).compact();
        String noRole = Jwts.builder().issuer("village-server").subject("1")
                .claim("sid", "s").expiration(exp).signWith(key).compact();
        String unknownRole = Jwts.builder().issuer("village-server").subject("1")
                .claim("role", "SUPERUSER").claim("sid", "s").expiration(exp).signWith(key).compact();

        assertThat(provider.parse(otherIssuer)).isEmpty();
        assertThat(provider.parse(noRole)).isEmpty();
        assertThat(provider.parse(unknownRole)).isEmpty();
    }

    @Test
    void 서명없는_토큰은_거부() {
        JwtProvider provider = new JwtProvider(props(SECRET, 1800));
        String unsigned = Jwts.builder().issuer("village-server").subject("1")
                .claim("role", "ADMIN").claim("sid", "s")
                .expiration(Date.from(Instant.now().plusSeconds(600))).compact();

        assertThat(provider.parse(unsigned)).isEmpty();
    }

    private static AppProperties props(String secret, long ttl) {
        return new AppProperties(new AppProperties.Jwt(secret, ttl), null, null, null, null);
    }
}
