package com.connect11.server.domain.auth.service.impl;

import com.connect11.server.domain.auth.dto.request.LoginRequest;
import com.connect11.server.domain.auth.dto.response.LoginResponse;
import com.connect11.server.domain.auth.dto.response.TokenRefreshResponse;
import com.connect11.server.domain.auth.repository.LoginAttemptLimiter;
import com.connect11.server.domain.auth.repository.RefreshSessionStore;
import com.connect11.server.domain.auth.service.AuthService;
import com.connect11.server.domain.user.entity.User;
import com.connect11.server.domain.user.repository.UserRepository;
import com.connect11.server.global.config.AppProperties;
import com.connect11.server.global.exception.BusinessException;
import com.connect11.server.global.exception.ErrorCode;
import com.connect11.server.global.security.JwtProvider;
import com.connect11.server.global.security.SecretHasher;
import com.connect11.server.global.util.EmailNormalizer;
import com.connect11.server.global.util.PasswordPolicy;
import com.connect11.server.global.util.SecureRandoms;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Slf4j
@Service
public class AuthServiceImpl implements AuthService {

    static final int MAX_LOGIN_ATTEMPTS = 5;                        // 이메일+IP 기준
    static final Duration LOGIN_WINDOW = Duration.ofMinutes(15);

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtProvider jwtProvider;
    private final RefreshSessionStore sessionStore;
    private final LoginAttemptLimiter loginLimiter;
    private final SecretHasher hasher;
    private final Duration refreshTtl;
    // 없는 계정도 BCrypt 비교를 한 번 수행해 응답 시간으로 가입 여부가 드러나지 않게 한다.
    private final String dummyHash;

    public AuthServiceImpl(UserRepository userRepository, PasswordEncoder passwordEncoder, JwtProvider jwtProvider,
                           RefreshSessionStore sessionStore, LoginAttemptLimiter loginLimiter, SecretHasher hasher,
                           AppProperties properties) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtProvider = jwtProvider;
        this.sessionStore = sessionStore;
        this.loginLimiter = loginLimiter;
        this.hasher = hasher;
        this.refreshTtl = Duration.ofSeconds(properties.auth().refreshTokenTtlSeconds());
        this.dummyHash = passwordEncoder.encode(SecureRandoms.opaqueToken());
    }

    @Override
    public LoginResult login(LoginRequest request, String clientIp) {
        String email = EmailNormalizer.normalize(request.username());

        // 비밀번호를 확인하기 전에 시도 횟수를 먼저 올린다. (동시에 여러 번 찔러도 제한을 넘길 수 없다)
        String limitKey = hasher.hmac("login:" + email + "|" + clientIp);
        if (loginLimiter.increment(limitKey, LOGIN_WINDOW) > MAX_LOGIN_ATTEMPTS) {
            throw new BusinessException(ErrorCode.LOGIN_RATE_LIMITED);
        }

        User user = userRepository.findByEmail(email).orElse(null);
        boolean passwordMatches = matches(request.password(), user == null ? dummyHash : user.getPasswordHash());
        if (user == null || !passwordMatches) {
            throw new BusinessException(ErrorCode.AUTHENTICATION_FAILED);
        }
        if (!user.isActive()) {
            throw new BusinessException(ErrorCode.ACCOUNT_INACTIVE);
        }

        loginLimiter.reset(limitKey);
        RefreshSessionStore.Issued session = sessionStore.create(user.getId(), refreshTtl);
        String accessToken = jwtProvider.createAccessToken(user.getId(), user.getRole(), session.sessionId());
        LoginResponse body = LoginResponse.of(accessToken, jwtProvider.getAccessTokenTtlSeconds(), refreshTtl.toSeconds(),
                new LoginResponse.UserSummary(user.getId(), user.getName(), user.getRole()));
        return new LoginResult(body, session.refreshToken());
    }

    @Override
    public RefreshResult refresh(String refreshToken) {
        if (refreshToken == null || refreshToken.isBlank()) {
            throw new BusinessException(ErrorCode.UNAUTHENTICATED);
        }
        RefreshSessionStore.RotateResult result = sessionStore.rotate(refreshToken, refreshTtl);
        switch (result.status()) {
            case OK -> {
            }
            case EXPIRED -> throw new BusinessException(ErrorCode.REFRESH_TOKEN_EXPIRED);
            case REVOKED -> throw new BusinessException(ErrorCode.REFRESH_TOKEN_REVOKED);
            case REUSED -> {
                // 이미 회전된 토큰이 다시 쓰였다. 탈취 가능성이 있으므로 세션은 이미 폐기되었다.
                log.warn("refresh token 재사용 탐지: userId={}", result.userId());
                throw new BusinessException(ErrorCode.REFRESH_TOKEN_REVOKED);
            }
            default -> throw new BusinessException(ErrorCode.REFRESH_TOKEN_INVALID);
        }

        User user = userRepository.findById(result.userId()).orElse(null);
        if (user == null) {
            sessionStore.revokeSession(result.sessionId());
            throw new BusinessException(ErrorCode.REFRESH_TOKEN_INVALID);
        }
        if (!user.isActive()) {
            sessionStore.revokeSession(result.sessionId());
            throw new BusinessException(ErrorCode.ACCOUNT_INACTIVE);
        }

        // 권한은 DB의 최신 값으로 다시 발급한다.
        String accessToken = jwtProvider.createAccessToken(user.getId(), user.getRole(), result.sessionId());
        return new RefreshResult(
                TokenRefreshResponse.of(accessToken, jwtProvider.getAccessTokenTtlSeconds(), refreshTtl.toSeconds()),
                result.refreshToken());
    }

    @Override
    public void logout(Long userId, String sessionId, String refreshToken) {
        if (refreshToken == null || refreshToken.isBlank()) {
            // 쿠키가 이미 지워졌어도 서명된 access token의 세션은 폐기한다. 세션이 없으면 이미 끝난 것이므로 성공이다.
            sessionStore.revokeSessionOwned(sessionId, userId);
            return;
        }
        // access token 주체의 세션이 아니거나 유효하지 않은 토큰이면 거부. 이미 폐기된 세션은 성공으로 본다.
        if (!sessionStore.revokeOwned(refreshToken, userId)) {
            throw new BusinessException(ErrorCode.REFRESH_TOKEN_INVALID);
        }
    }

    // BCrypt는 72바이트 초과 입력을 거부할 수 있으므로 미리 걸러 불일치로 처리한다.
    private boolean matches(String rawPassword, String hash) {
        boolean tooLong = rawPassword.getBytes(StandardCharsets.UTF_8).length > PasswordPolicy.MAX_LENGTH;
        boolean matched = passwordEncoder.matches(tooLong ? "" : rawPassword, hash);
        return matched && !tooLong;
    }
}
