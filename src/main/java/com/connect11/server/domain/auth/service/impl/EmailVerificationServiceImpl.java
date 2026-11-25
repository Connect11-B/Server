package com.connect11.server.domain.auth.service.impl;

import com.connect11.server.domain.auth.dto.request.*;
import com.connect11.server.domain.auth.dto.response.*;
import com.connect11.server.domain.auth.entity.EmailVerification;
import com.connect11.server.domain.auth.entity.VerificationPurpose;
import com.connect11.server.domain.auth.exception.AuthErrorCode;
import com.connect11.server.domain.auth.repository.EmailSendRateLimiter;
import com.connect11.server.domain.auth.repository.EmailVerificationStore;
import com.connect11.server.domain.auth.repository.VerificationTokenStore;
import com.connect11.server.domain.auth.service.EmailVerificationService;
import com.connect11.server.domain.auth.service.VerificationMailSender;
import com.connect11.server.domain.user.repository.UserRepository;
import com.connect11.server.global.exception.CustomException;
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

    static final Duration CODE_TTL = Duration.ofMinutes(10);
    static final Duration RESEND_AFTER = Duration.ofSeconds(60);
    static final Duration HOURLY_WINDOW = Duration.ofHours(1);
    static final int HOURLY_LIMIT = 5;
    static final int IP_HOURLY_LIMIT = 20;
    static final int MAX_ATTEMPTS = 5;
    static final Duration TOKEN_TTL = Duration.ofMinutes(10);
    static final Duration EXPIRED_GRACE = Duration.ofHours(1);

    private final EmailVerificationStore verificationStore;
    private final VerificationTokenStore tokenStore;
    private final EmailSendRateLimiter rateLimiter;
    private final UserRepository userRepository;
    private final VerificationMailSender mailSender;
    private final SecretHasher hasher;
    private final Clock clock;

    @Override
    public EmailSendResponse send(EmailSendRequest request, String clientIp) {
        String email = EmailNormalizer.normalize(request.email());
        VerificationPurpose purpose = request.purpose();
        String emailKey = hasher.emailHash(email);

        if (rateLimiter.incrementIpHourly(hasher.hmac("ip:" + clientIp), HOURLY_WINDOW) > IP_HOURLY_LIMIT) {
            throw new CustomException(AuthErrorCode.EMAIL_RATE_LIMITED);
        }

        if (!rateLimiter.tryAcquireCooldown(emailKey, RESEND_AFTER)) {
            throw new CustomException(AuthErrorCode.EMAIL_RATE_LIMITED);
        }
        if (rateLimiter.incrementHourly(emailKey, HOURLY_WINDOW) > HOURLY_LIMIT) {
            throw new CustomException(AuthErrorCode.EMAIL_RATE_LIMITED);
        }

        boolean registered = userRepository.existsByEmail(email);
        if (purpose == VerificationPurpose.SIGNUP && registered) {
            throw new CustomException(AuthErrorCode.EMAIL_ALREADY_REGISTERED);
        }

        String id = UUID.randomUUID().toString();
        String code = SecureRandoms.sixCode();
        long expiresAt = clock.instant().plus(CODE_TTL).getEpochSecond();
        verificationStore.save(
                new EmailVerification(id, email, purpose, hasher.codeHash(id, code), expiresAt, false),
                CODE_TTL.plus(EXPIRED_GRACE));
        verificationStore.replaceLatest(emailKey, purpose, id, CODE_TTL.plus(EXPIRED_GRACE))
                .ifPresent(verificationStore::delete);

        boolean shouldSend = purpose == VerificationPurpose.SIGNUP || registered;
        if (shouldSend) {
            try {
                mailSender.sendCode(email, code, purpose);
            } catch (RuntimeException e) {
                log.warn("인증 메일 발송 실패: purpose={} cause={}", purpose, e.getClass().getSimpleName());
                verificationStore.delete(id);
                rateLimiter.releaseCooldown(emailKey);
                throw new CustomException(AuthErrorCode.EMAIL_SEND_FAILED);
            }
        }
        return new EmailSendResponse(id, CODE_TTL.toSeconds(), RESEND_AFTER.toSeconds());
    }

    @Override
    public EmailVerifyResponse verify(EmailVerifyRequest request) {
        EmailVerification v = verificationStore.find(request.verificationId())
                .orElseThrow(() -> new CustomException(AuthErrorCode.EMAIL_VERIFICATION_INVALID));

        if (v.used()) {
            throw new CustomException(AuthErrorCode.EMAIL_VERIFICATION_ALREADY_USED);
        }
        if (clock.instant().getEpochSecond() >= v.expiresAtEpochSecond()) {
            throw new CustomException(AuthErrorCode.EMAIL_VERIFICATION_EXPIRED);
        }

        long attempt = verificationStore.incrementAttempts(v.id());
        if (attempt < 0) {
            throw new CustomException(AuthErrorCode.EMAIL_VERIFICATION_INVALID);
        }
        if (attempt > MAX_ATTEMPTS) {
            throw new CustomException(AuthErrorCode.EMAIL_VERIFICATION_ATTEMPTS_EXCEEDED);
        }

        String candidate = hasher.codeHash(v.id(), request.code());
        if (!SecretHasher.constantTimeEquals(candidate, v.codeHash())) {
            throw new CustomException(attempt == MAX_ATTEMPTS
                    ? AuthErrorCode.EMAIL_VERIFICATION_ATTEMPTS_EXCEEDED
                    : AuthErrorCode.EMAIL_VERIFICATION_INVALID);
        }

        if (!verificationStore.markUsed(v.id())) {
            throw new CustomException(AuthErrorCode.EMAIL_VERIFICATION_ALREADY_USED);
        }

        long tokenExpiresAt = clock.instant().plus(TOKEN_TTL).getEpochSecond();
        String token = tokenStore.issue(v.purpose(), v.email(), tokenExpiresAt, TOKEN_TTL.plus(EXPIRED_GRACE));
        return EmailVerifyResponse.of(v.purpose(), token, TOKEN_TTL.toSeconds());
    }
}
