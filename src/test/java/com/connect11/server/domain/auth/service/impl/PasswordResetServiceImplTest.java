package com.connect11.server.domain.auth.service.impl;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.connect11.server.domain.auth.dto.request.PasswordResetRequest;
import com.connect11.server.domain.auth.dto.response.PasswordResetResponse;
import com.connect11.server.domain.auth.entity.VerificationPurpose;
import com.connect11.server.domain.auth.entity.VerificationToken;
import com.connect11.server.domain.auth.repository.RefreshSessionStore;
import com.connect11.server.domain.auth.repository.VerificationTokenStore;
import com.connect11.server.domain.user.entity.User;
import com.connect11.server.domain.user.repository.UserRepository;
import com.connect11.server.global.exception.BusinessException;
import com.connect11.server.global.exception.ErrorCode;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import org.assertj.core.api.Assertions;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

class PasswordResetServiceImplTest {

    private static final Instant NOW = Instant.parse("2026-11-24T00:00:00Z");
    private static final String TOKEN = "reset-token";
    private static final String EMAIL = "student@school.kr";
    private static final String NEW_PASSWORD = "NewPassword123!";

    private VerificationTokenStore tokenStore;
    private UserRepository userRepository;
    private RefreshSessionStore sessionStore;
    private PasswordEncoder encoder;
    private PasswordResetServiceImpl service;
    private User user;

    @BeforeEach
    void setUp() {
        tokenStore = mock(VerificationTokenStore.class);
        userRepository = mock(UserRepository.class);
        sessionStore = mock(RefreshSessionStore.class);
        encoder = new BCryptPasswordEncoder(4);
        service = new PasswordResetServiceImpl(tokenStore, userRepository, sessionStore, encoder,
                Clock.fixed(NOW, ZoneOffset.UTC));

        user = User.createStudent(EMAIL, encoder.encode("OldPassword123!"), "학생", "1234");
        ReflectionTestUtils.setField(user, "id", 7L);
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(user));
    }

    private void tokenIs(boolean used, long expiresAt) {
        when(tokenStore.find(VerificationPurpose.PASSWORD_RESET, TOKEN)).thenReturn(Optional.of(
                new VerificationToken(VerificationPurpose.PASSWORD_RESET, EMAIL, expiresAt, used)));
    }

    private void validToken() {
        tokenIs(false, NOW.getEpochSecond() + 300);
        when(tokenStore.markUsed(VerificationPurpose.PASSWORD_RESET, TOKEN)).thenReturn(true);
    }

    private ErrorCode errorOf(ThrowingCallable callable) {
        return ((BusinessException) Assertions.catchThrowable(callable)).getErrorCode();
    }

    @Test
    void 재설정에_성공하면_비밀번호가_바뀌고_모든_세션이_폐기된다() {
        validToken();

        PasswordResetResponse response = service.reset(TOKEN, new PasswordResetRequest(NEW_PASSWORD));

        assertThat(response.passwordUpdated()).isTrue();
        assertThat(encoder.matches(NEW_PASSWORD, user.getPasswordHash())).isTrue();
        assertThat(encoder.matches("OldPassword123!", user.getPasswordHash())).isFalse();
        verify(userRepository).save(user);
        verify(sessionStore).revokeAllForUser(7L);
        verify(tokenStore).markUsed(VerificationPurpose.PASSWORD_RESET, TOKEN);
    }

    @Test
    void 토큰이_없거나_비어_있으면_401_RESET_TOKEN_INVALID() {
        assertThat(errorOf(() -> service.reset(null, new PasswordResetRequest(NEW_PASSWORD))))
                .isEqualTo(ErrorCode.RESET_TOKEN_INVALID);
        assertThat(errorOf(() -> service.reset("  ", new PasswordResetRequest(NEW_PASSWORD))))
                .isEqualTo(ErrorCode.RESET_TOKEN_INVALID);
    }

    @Test
    void 모르는_토큰이면_401() {
        when(tokenStore.find(VerificationPurpose.PASSWORD_RESET, TOKEN)).thenReturn(Optional.empty());

        assertThat(errorOf(() -> service.reset(TOKEN, new PasswordResetRequest(NEW_PASSWORD))))
                .isEqualTo(ErrorCode.RESET_TOKEN_INVALID);
        verify(sessionStore, never()).revokeAllForUser(any());
    }

    @Test
    void 이미_사용한_토큰은_409() {
        tokenIs(true, NOW.getEpochSecond() + 300);

        assertThat(errorOf(() -> service.reset(TOKEN, new PasswordResetRequest(NEW_PASSWORD))))
                .isEqualTo(ErrorCode.RESET_TOKEN_ALREADY_USED);
    }

    @Test
    void 만료된_토큰은_410() {
        tokenIs(false, NOW.getEpochSecond());

        assertThat(errorOf(() -> service.reset(TOKEN, new PasswordResetRequest(NEW_PASSWORD))))
                .isEqualTo(ErrorCode.RESET_TOKEN_EXPIRED);
    }

    @Test
    void 비밀번호_정책을_어기면_400이고_토큰은_소비되지_않는다() {
        validToken();

        assertThat(errorOf(() -> service.reset(TOKEN, new PasswordResetRequest("short1"))))
                .isEqualTo(ErrorCode.PASSWORD_POLICY_VIOLATION);
        verify(tokenStore, never()).markUsed(any(), any());
        verify(sessionStore, never()).revokeAllForUser(any());
    }

    @Test
    void 토큰의_이메일에_해당하는_계정이_없으면_401() {
        validToken();
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.empty());

        assertThat(errorOf(() -> service.reset(TOKEN, new PasswordResetRequest(NEW_PASSWORD))))
                .isEqualTo(ErrorCode.RESET_TOKEN_INVALID);
        verify(tokenStore, never()).markUsed(any(), any());
    }

    @Test
    void 동시에_같은_토큰을_쓰면_소비에_실패한_쪽은_409이고_세션을_건드리지_않는다() {
        tokenIs(false, NOW.getEpochSecond() + 300);
        when(tokenStore.markUsed(VerificationPurpose.PASSWORD_RESET, TOKEN)).thenReturn(false);

        assertThat(errorOf(() -> service.reset(TOKEN, new PasswordResetRequest(NEW_PASSWORD))))
                .isEqualTo(ErrorCode.RESET_TOKEN_ALREADY_USED);
        verify(userRepository, never()).save(any());
        verify(sessionStore, never()).revokeAllForUser(any());
    }
}
