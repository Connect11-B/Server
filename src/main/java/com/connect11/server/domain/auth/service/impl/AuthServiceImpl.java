package com.connect11.server.domain.auth.service.impl;

import com.connect11.server.domain.auth.dto.request.LoginRequest;
import com.connect11.server.domain.auth.dto.response.LoginResponse;
import com.connect11.server.domain.auth.dto.response.TokenRefreshResponse;
import com.connect11.server.domain.auth.exception.AuthErrorCode;
import com.connect11.server.domain.auth.repository.LoginAttemptLimiter;
import com.connect11.server.domain.auth.repository.RefreshSessionStore;
import com.connect11.server.domain.auth.service.AuthService;
import com.connect11.server.domain.user.entity.User;
import com.connect11.server.domain.user.repository.UserRepository;
import com.connect11.server.global.config.AppProperties;
import com.connect11.server.global.exception.CustomException;
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

    static final int MAX_LOGIN_ATTEMPTS = 5;
    static final Duration LOGIN_WINDOW = Duration.ofMinutes(15);

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtProvider jwtProvider;
    private final RefreshSessionStore sessionStore;
    private final LoginAttemptLimiter loginLimiter;
    private final SecretHasher hasher;
    private final Duration refreshTtl;
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

        String limitKey = hasher.hmac("login:" + email + "|" + clientIp);
        if (loginLimiter.increment(limitKey, LOGIN_WINDOW) > MAX_LOGIN_ATTEMPTS) {
            throw new CustomException(AuthErrorCode.LOGIN_RATE_LIMITED);
        }

        User user = userRepository.findByEmail(email).orElse(null);
        boolean passwordMatches = matches(request.password(), user == null ? dummyHash : user.getPasswordHash());
        if (user == null || !passwordMatches) {
            throw new CustomException(AuthErrorCode.AUTHENTICATION_FAILED);
        }
        if (!user.isActive()) {
            throw new CustomException(AuthErrorCode.ACCOUNT_INACTIVE);
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
            throw new CustomException(ErrorCode.UNAUTHENTICATED);
        }
        RefreshSessionStore.RotateResult result = sessionStore.rotate(refreshToken, refreshTtl);
        switch (result.status()) {
            case OK -> {
            }
            case EXPIRED -> throw new CustomException(AuthErrorCode.REFRESH_TOKEN_EXPIRED);
            case REVOKED -> throw new CustomException(AuthErrorCode.REFRESH_TOKEN_REVOKED);
            case REUSED -> {
                log.warn("refresh token 재사용 탐지: userId={}", result.userId());
                throw new CustomException(AuthErrorCode.REFRESH_TOKEN_REVOKED);
            }
            default -> throw new CustomException(AuthErrorCode.REFRESH_TOKEN_INVALID);
        }

        User user = userRepository.findById(result.userId()).orElse(null);
        if (user == null) {
            sessionStore.revokeSession(result.sessionId());
            throw new CustomException(AuthErrorCode.REFRESH_TOKEN_INVALID);
        }
        if (!user.isActive()) {
            sessionStore.revokeSession(result.sessionId());
            throw new CustomException(AuthErrorCode.ACCOUNT_INACTIVE);
        }

        String accessToken = jwtProvider.createAccessToken(user.getId(), user.getRole(), result.sessionId());
        return new RefreshResult(
                TokenRefreshResponse.of(accessToken, jwtProvider.getAccessTokenTtlSeconds(), refreshTtl.toSeconds()),
                result.refreshToken());
    }

    @Override
    public void logout(Long userId, String sessionId, String refreshToken) {
        if (refreshToken == null || refreshToken.isBlank()) {
            sessionStore.revokeSessionOwned(sessionId, userId);
            return;
        }
        boolean sameSession = RefreshSessionStore.sessionIdOf(refreshToken)
                .filter(sid -> sid.equals(sessionId))
                .isPresent();
        if (!sameSession) {
            sessionStore.revokeSessionOwned(sessionId, userId);
            throw new CustomException(AuthErrorCode.REFRESH_TOKEN_INVALID);
        }
        if (!sessionStore.revokeOwned(refreshToken, userId)) {
            throw new CustomException(AuthErrorCode.REFRESH_TOKEN_INVALID);
        }
    }

    private boolean matches(String rawPassword, String hash) {
        boolean tooLong = rawPassword.getBytes(StandardCharsets.UTF_8).length > PasswordPolicy.MAX_LENGTH;
        boolean matched = passwordEncoder.matches(tooLong ? "" : rawPassword, hash);
        return matched && !tooLong;
    }
}
