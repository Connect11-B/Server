package com.connect11.server.domain.auth.service.impl;

import com.connect11.server.domain.auth.dto.request.*;
import com.connect11.server.domain.auth.dto.response.*;
import com.connect11.server.domain.auth.entity.EmailVerification;
import com.connect11.server.domain.auth.entity.VerificationPurpose;
import com.connect11.server.domain.auth.repository.EmailSendRateLimiter;
import com.connect11.server.domain.auth.repository.EmailVerificationStore;
import com.connect11.server.domain.auth.repository.VerificationTokenStore;
import com.connect11.server.domain.auth.service.EmailVerificationService;
import com.connect11.server.domain.auth.service.VerificationMailSender;
import com.connect11.server.domain.user.repository.UserRepository;
import com.connect11.server.global.exception.BusinessException;
import com.connect11.server.global.exception.ErrorCode;
import com.connect11.server.global.security.SecretHasher;
import com.connect11.server.global.util.EmailNormalizer;
import com.connect11.server.global.util.SecureRandoms;
import java.time.Clock;
import java.time.Duration;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class EmailVerificationServiceImpl implements EmailVerificationService {

    static final Duration CODE_TTL = Duration.ofMinutes(10);        // expiresIn 600
    static final Duration RESEND_AFTER = Duration.ofSeconds(60);    // resendAfter 60
    static final Duration HOURLY_WINDOW = Duration.ofHours(1);
    static final int HOURLY_LIMIT = 5;
    static final int MAX_ATTEMPTS = 5;
    static final Duration TOKEN_TTL = Duration.ofMinutes(10);       // signupToken·resetToken 유효 시간
    // 만료 후에도 키를 잠시 남겨 EXPIRED와 INVALID를 구분한다.
    static final Duration EXPIRED_GRACE = Duration.ofHours(1);

    private final EmailVerificationStore verificationStore;
    private final VerificationTokenStore tokenStore;
    private final EmailSendRateLimiter rateLimiter;
    private final UserRepository userRepository;
    private final VerificationMailSender mailSender;
    private final SecretHasher hasher;
    private final Clock clock;

    @Override
    public EmailSendResponse send(EmailSendRequest request) {
        String email = EmailNormalizer.normalize(request.email());
        VerificationPurpose purpose = request.purpose();
        String emailKey = hasher.emailHash(email);

        // 1) 발송 제한을 가장 먼저 검사 (가입 여부 조회를 반복 시도하는 것도 함께 제한)
        if (!rateLimiter.tryAcquireCooldown(emailKey, RESEND_AFTER)) {
            throw new BusinessException(ErrorCode.EMAIL_RATE_LIMITED);
        }
        if (rateLimiter.incrementHourly(emailKey, HOURLY_WINDOW) > HOURLY_LIMIT) {
            throw new BusinessException(ErrorCode.EMAIL_RATE_LIMITED);
        }

        boolean registered = userRepository.existsByEmail(email);
        if (purpose == VerificationPurpose.SIGNUP && registered) {
            throw new BusinessException(ErrorCode.EMAIL_ALREADY_REGISTERED);
        }

        // 2) 인증 건 저장. 미가입 이메일의 비밀번호 재설정도 똑같이 저장만 하고 메일은 보내지 않는다.
        //    (응답·검증 동작을 같게 만들어 가입 여부가 드러나지 않게 함)
        String id = UUID.randomUUID().toString();
        String code = SecureRandoms.sixCode();
        long expiresAt = clock.instant().plus(CODE_TTL).getEpochSecond();
        verificationStore.save(
                new EmailVerification(id, email, purpose, hasher.codeHash(id, code), expiresAt, false),
                CODE_TTL.plus(EXPIRED_GRACE));
        // 재발송하면 이전 코드는 무효
        verificationStore.replaceLatest(emailKey, purpose, id, CODE_TTL.plus(EXPIRED_GRACE))
                .ifPresent(verificationStore::delete);

        boolean shouldSend = purpose == VerificationPurpose.SIGNUP || registered;
        if (shouldSend) {
            try {
                mailSender.sendCode(email, code, purpose);
            } catch (RuntimeException e) {
                // 코드·이메일 원문은 로그에 남기지 않는다.
                log.warn("인증 메일 발송 실패: purpose={} cause={}", purpose, e.getClass().getSimpleName());
                verificationStore.delete(id);
                rateLimiter.releaseCooldown(emailKey);
                throw new BusinessException(ErrorCode.EMAIL_SEND_FAILED);
            }
        }
        return new EmailSendResponse(id, CODE_TTL.toSeconds(), RESEND_AFTER.toSeconds());
    }

    @Override
    public EmailVerifyResponse verify(EmailVerifyRequest request) {
        EmailVerification v = verificationStore.find(request.verificationId())
                .orElseThrow(() -> new BusinessException(ErrorCode.EMAIL_VERIFICATION_INVALID));

        if (v.used()) {
            throw new BusinessException(ErrorCode.EMAIL_VERIFICATION_ALREADY_USED);
        }
        if (clock.instant().getEpochSecond() >= v.expiresAtEpochSecond()) {
            throw new BusinessException(ErrorCode.EMAIL_VERIFICATION_EXPIRED);
        }

        // 비교 전에 시도 횟수를 먼저 올린다. 동시에 여러 번 찔러도 5회를 넘길 수 없다.
        long attempt = verificationStore.incrementAttempts(v.id());
        if (attempt < 0) {
            throw new BusinessException(ErrorCode.EMAIL_VERIFICATION_INVALID);
        }
        if (attempt > MAX_ATTEMPTS) {
            throw new BusinessException(ErrorCode.EMAIL_VERIFICATION_ATTEMPTS_EXCEEDED);
        }

        String candidate = hasher.codeHash(v.id(), request.code());
        if (!SecretHasher.constantTimeEquals(candidate, v.codeHash())) {
            throw new BusinessException(attempt == MAX_ATTEMPTS
                    ? ErrorCode.EMAIL_VERIFICATION_ATTEMPTS_EXCEEDED
                    : ErrorCode.EMAIL_VERIFICATION_INVALID);
        }

        // 동시에 맞는 코드로 요청해도 토큰은 한 번만 발급된다.
        if (!verificationStore.markUsed(v.id())) {
            throw new BusinessException(ErrorCode.EMAIL_VERIFICATION_ALREADY_USED);
        }

        long tokenExpiresAt = clock.instant().plus(TOKEN_TTL).getEpochSecond();
        String token = tokenStore.issue(v.purpose(), v.email(), tokenExpiresAt, TOKEN_TTL.plus(EXPIRED_GRACE));
        return EmailVerifyResponse.of(v.purpose(), token, TOKEN_TTL.toSeconds());
    }
}

