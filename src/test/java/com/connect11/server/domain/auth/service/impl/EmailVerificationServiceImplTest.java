package com.connect11.server.domain.auth.service.impl;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.connect11.server.domain.auth.dto.request.EmailSendRequest;
import com.connect11.server.domain.auth.dto.request.EmailVerifyRequest;
import com.connect11.server.domain.auth.dto.response.EmailSendResponse;
import com.connect11.server.domain.auth.dto.response.EmailVerifyResponse;
import com.connect11.server.domain.auth.entity.EmailVerification;
import com.connect11.server.domain.auth.entity.VerificationPurpose;
import com.connect11.server.domain.auth.exception.AuthErrorCode;
import com.connect11.server.domain.auth.repository.EmailSendRateLimiter;
import com.connect11.server.domain.auth.repository.EmailVerificationStore;
import com.connect11.server.domain.auth.repository.VerificationTokenStore;
import com.connect11.server.domain.auth.service.VerificationMailSender;
import com.connect11.server.domain.user.repository.UserRepository;
import com.connect11.server.global.common.CustomErrorCode;
import com.connect11.server.global.config.AppProperties;
import com.connect11.server.global.exception.CustomException;
import com.connect11.server.global.security.SecretHasher;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class EmailVerificationServiceImplTest {

    private static final Instant NOW = Instant.parse("2026-11-18T00:00:00Z");
    private static final String ID = "verification-id";
    private static final String EMAIL = "student@school.kr";
    private static final String IP = "203.0.113.7";

    private EmailVerificationStore verificationStore;
    private VerificationTokenStore tokenStore;
    private EmailSendRateLimiter rateLimiter;
    private UserRepository userRepository;
    private VerificationMailSender mailSender;
    private SecretHasher hasher;
    private EmailVerificationServiceImpl service;

    @BeforeEach
    void setUp() {
        verificationStore = mock(EmailVerificationStore.class);
        tokenStore = mock(VerificationTokenStore.class);
        rateLimiter = mock(EmailSendRateLimiter.class);
        userRepository = mock(UserRepository.class);
        mailSender = mock(VerificationMailSender.class);
        hasher = new SecretHasher(new AppProperties(null,
                new AppProperties.Auth("test-only-pepper-not-for-production", 1209600, true, "Strict"),
                null, new AppProperties.Cors(List.of()), null));
        service = new EmailVerificationServiceImpl(verificationStore, tokenStore, rateLimiter,
                userRepository, mailSender, hasher, Clock.fixed(NOW, ZoneOffset.UTC));

        when(rateLimiter.tryAcquireCooldown(anyString(), any())).thenReturn(true);
        when(rateLimiter.incrementHourly(anyString(), any())).thenReturn(1L);
        when(rateLimiter.incrementIpHourly(anyString(), any())).thenReturn(1L);
        when(verificationStore.replaceLatest(anyString(), any(), anyString(), any())).thenReturn(Optional.empty());
    }

    @Test
    void 회원가입_코드_발송_성공() {
        when(userRepository.existsByEmail(EMAIL)).thenReturn(false);

        EmailSendResponse response = service.send(new EmailSendRequest("  Student@School.kr ", VerificationPurpose.SIGNUP), IP);

        assertThat(response.expiresIn()).isEqualTo(600);
        assertThat(response.resendAfter()).isEqualTo(60);
        verify(mailSender).sendCode(eq(EMAIL), anyString(), eq(VerificationPurpose.SIGNUP));
    }

    @Test
    void 이미_가입된_이메일로_회원가입_코드_요청시_409() {
        when(userRepository.existsByEmail(EMAIL)).thenReturn(true);

        assertError(() -> service.send(new EmailSendRequest(EMAIL, VerificationPurpose.SIGNUP), IP),
                AuthErrorCode.EMAIL_ALREADY_REGISTERED);
        verify(mailSender, never()).sendCode(anyString(), anyString(), any());
    }

    @Test
    void 미가입_이메일의_비밀번호_재설정은_정상_응답하지만_메일은_보내지_않는다() {
        when(userRepository.existsByEmail(EMAIL)).thenReturn(false);

        EmailSendResponse response = service.send(new EmailSendRequest(EMAIL, VerificationPurpose.PASSWORD_RESET), IP);

        assertThat(response.verificationId()).isNotBlank();
        verify(verificationStore).save(any(), any());
        verify(mailSender, never()).sendCode(anyString(), anyString(), any());
    }

    @Test
    void 재발송_대기시간_중이면_429() {
        when(rateLimiter.tryAcquireCooldown(anyString(), any())).thenReturn(false);

        assertError(() -> service.send(new EmailSendRequest(EMAIL, VerificationPurpose.SIGNUP), IP),
                AuthErrorCode.EMAIL_RATE_LIMITED);
    }

    @Test
    void 시간당_5회_초과시_429() {
        when(rateLimiter.incrementHourly(anyString(), any())).thenReturn(6L);

        assertError(() -> service.send(new EmailSendRequest(EMAIL, VerificationPurpose.SIGNUP), IP),
                AuthErrorCode.EMAIL_RATE_LIMITED);
    }

    @Test
    void 메일_발송_실패시_인증건_삭제하고_503() {
        when(userRepository.existsByEmail(EMAIL)).thenReturn(false);
        doThrow(new RuntimeException("smtp down"))
                .when(mailSender).sendCode(anyString(), anyString(), any());

        assertError(() -> service.send(new EmailSendRequest(EMAIL, VerificationPurpose.SIGNUP), IP),
                AuthErrorCode.EMAIL_SEND_FAILED);
        verify(verificationStore).delete(anyString());
        verify(rateLimiter).releaseCooldown(anyString());
    }

    @Test
    void 올바른_코드면_signupToken_발급() {
        givenVerification(VerificationPurpose.SIGNUP, "123456", NOW.plusSeconds(600), false);
        when(verificationStore.incrementAttempts(ID)).thenReturn(1L);
        when(verificationStore.markUsed(ID)).thenReturn(true);
        when(tokenStore.issue(eq(VerificationPurpose.SIGNUP), eq(EMAIL), anyLong(), any())).thenReturn("signup-token");

        EmailVerifyResponse response = service.verify(new EmailVerifyRequest(ID, "123456"));

        assertThat(response.purpose()).isEqualTo(VerificationPurpose.SIGNUP);
        assertThat(response.signupToken()).isEqualTo("signup-token");
        assertThat(response.resetToken()).isNull();
        assertThat(response.expiresIn()).isEqualTo(600);
    }

    @Test
    void 비밀번호_재설정이면_resetToken_발급() {
        givenVerification(VerificationPurpose.PASSWORD_RESET, "123456", NOW.plusSeconds(600), false);
        when(verificationStore.incrementAttempts(ID)).thenReturn(1L);
        when(verificationStore.markUsed(ID)).thenReturn(true);
        when(tokenStore.issue(eq(VerificationPurpose.PASSWORD_RESET), eq(EMAIL), anyLong(), any()))
                .thenReturn("reset-token");

        EmailVerifyResponse response = service.verify(new EmailVerifyRequest(ID, "123456"));

        assertThat(response.resetToken()).isEqualTo("reset-token");
        assertThat(response.signupToken()).isNull();
    }

    @Test
    void 틀린_코드면_401_다섯번째는_429() {
        givenVerification(VerificationPurpose.SIGNUP, "123456", NOW.plusSeconds(600), false);

        when(verificationStore.incrementAttempts(ID)).thenReturn(1L);
        assertError(() -> service.verify(new EmailVerifyRequest(ID, "000000")), AuthErrorCode.EMAIL_VERIFICATION_INVALID);

        when(verificationStore.incrementAttempts(ID)).thenReturn(5L);
        assertError(() -> service.verify(new EmailVerifyRequest(ID, "000000")),
                AuthErrorCode.EMAIL_VERIFICATION_ATTEMPTS_EXCEEDED);
    }

    @Test
    void 시도_횟수_초과후에는_맞는_코드도_거부() {
        givenVerification(VerificationPurpose.SIGNUP, "123456", NOW.plusSeconds(600), false);
        when(verificationStore.incrementAttempts(ID)).thenReturn(6L);

        assertError(() -> service.verify(new EmailVerifyRequest(ID, "123456")),
                AuthErrorCode.EMAIL_VERIFICATION_ATTEMPTS_EXCEEDED);
        verify(tokenStore, never()).issue(any(), anyString(), anyLong(), any());
    }

    @Test
    void 만료된_코드는_410() {
        givenVerification(VerificationPurpose.SIGNUP, "123456", NOW.minusSeconds(1), false);

        assertError(() -> service.verify(new EmailVerifyRequest(ID, "123456")), AuthErrorCode.EMAIL_VERIFICATION_EXPIRED);
    }

    @Test
    void 이미_사용된_인증은_409() {
        givenVerification(VerificationPurpose.SIGNUP, "123456", NOW.plusSeconds(600), true);

        assertError(() -> service.verify(new EmailVerifyRequest(ID, "123456")),
                AuthErrorCode.EMAIL_VERIFICATION_ALREADY_USED);
    }

    @Test
    void 동시_요청으로_사용처리_경쟁에서_지면_409() {
        givenVerification(VerificationPurpose.SIGNUP, "123456", NOW.plusSeconds(600), false);
        when(verificationStore.incrementAttempts(ID)).thenReturn(1L);
        when(verificationStore.markUsed(ID)).thenReturn(false);

        assertError(() -> service.verify(new EmailVerifyRequest(ID, "123456")),
                AuthErrorCode.EMAIL_VERIFICATION_ALREADY_USED);
        verify(tokenStore, never()).issue(any(), anyString(), anyLong(), any());
    }

    @Test
    void 존재하지_않는_인증ID는_401() {
        when(verificationStore.find(ID)).thenReturn(Optional.empty());

        assertError(() -> service.verify(new EmailVerifyRequest(ID, "123456")), AuthErrorCode.EMAIL_VERIFICATION_INVALID);
    }

    private void givenVerification(VerificationPurpose purpose, String code, Instant expiresAt, boolean used) {
        when(verificationStore.find(ID)).thenReturn(Optional.of(new EmailVerification(
                ID, EMAIL, purpose, hasher.codeHash(ID, code), expiresAt.getEpochSecond(), used)));
    }

    private static void assertError(ThrowingCallable call, CustomErrorCode expected) {
        assertThatThrownBy(call)
                .isInstanceOf(CustomException.class)
                .extracting(e -> ((CustomException) e).getErrorCode())
                .isEqualTo(expected);
    }

    @Test
    void IP별_시간당_발송_한도를_넘으면_429이고_이메일_제한은_건드리지_않는다() {
        when(rateLimiter.incrementIpHourly(anyString(), any())).thenReturn(21L);

        assertError(() -> service.send(new EmailSendRequest("other@school.kr", VerificationPurpose.SIGNUP), IP),
                AuthErrorCode.EMAIL_RATE_LIMITED);
        verify(rateLimiter, never()).tryAcquireCooldown(anyString(), any());
        verify(mailSender, never()).sendCode(anyString(), anyString(), any());
    }

    @Test
    void IP별_한도는_20회까지_허용한다() {
        when(rateLimiter.incrementIpHourly(anyString(), any())).thenReturn(20L);
        when(userRepository.existsByEmail(EMAIL)).thenReturn(false);

        service.send(new EmailSendRequest(EMAIL, VerificationPurpose.SIGNUP), IP);

        verify(mailSender).sendCode(eq(EMAIL), anyString(), eq(VerificationPurpose.SIGNUP));
    }

    @Test
    void IP_제한_키에는_IP_원문이_들어가지_않는다() {
        when(userRepository.existsByEmail(EMAIL)).thenReturn(false);

        service.send(new EmailSendRequest(EMAIL, VerificationPurpose.SIGNUP), IP);

        org.mockito.ArgumentCaptor<String> key = org.mockito.ArgumentCaptor.forClass(String.class);
        verify(rateLimiter).incrementIpHourly(key.capture(), eq(java.time.Duration.ofHours(1)));
        assertThat(key.getValue()).doesNotContain(IP);
    }
}
