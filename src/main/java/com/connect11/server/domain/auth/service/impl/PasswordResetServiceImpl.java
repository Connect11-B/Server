package com.connect11.server.domain.auth.service.impl;

import com.connect11.server.domain.auth.dto.request.PasswordResetRequest;
import com.connect11.server.domain.auth.dto.response.PasswordResetResponse;
import com.connect11.server.domain.auth.entity.VerificationPurpose;
import com.connect11.server.domain.auth.entity.VerificationToken;
import com.connect11.server.domain.auth.repository.RefreshSessionStore;
import com.connect11.server.domain.auth.repository.VerificationTokenStore;
import com.connect11.server.domain.auth.service.PasswordResetService;
import com.connect11.server.domain.user.entity.User;
import com.connect11.server.domain.user.repository.UserRepository;
import com.connect11.server.global.exception.BusinessException;
import com.connect11.server.global.exception.ErrorCode;
import com.connect11.server.global.util.PasswordPolicy;
import java.time.Clock;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
public class PasswordResetServiceImpl implements PasswordResetService {

    private final VerificationTokenStore tokenStore;
    private final UserRepository userRepository;
    private final RefreshSessionStore sessionStore;
    private final PasswordEncoder passwordEncoder;
    private final Clock clock;

    @Override
    @Transactional
    public PasswordResetResponse reset(String resetToken, PasswordResetRequest request) {
        if (resetToken == null || resetToken.isBlank()) {
            throw new BusinessException(ErrorCode.RESET_TOKEN_INVALID);
        }

        VerificationToken saved = tokenStore.find(VerificationPurpose.PASSWORD_RESET, resetToken)
                .orElseThrow(() -> new BusinessException(ErrorCode.RESET_TOKEN_INVALID));
        if (saved.used()) {
            throw new BusinessException(ErrorCode.RESET_TOKEN_ALREADY_USED);
        }
        if (clock.instant().getEpochSecond() >= saved.expiresAtEpochSecond()) {
            throw new BusinessException(ErrorCode.RESET_TOKEN_EXPIRED);
        }

        if (!PasswordPolicy.isValid(request.newPassword())) {
            throw new BusinessException(ErrorCode.PASSWORD_POLICY_VIOLATION);
        }
        User user = userRepository.findByEmail(saved.email())
                .orElseThrow(() -> new BusinessException(ErrorCode.RESET_TOKEN_INVALID));

        if (!tokenStore.markUsed(VerificationPurpose.PASSWORD_RESET, resetToken)) {
            throw new BusinessException(ErrorCode.RESET_TOKEN_ALREADY_USED);
        }

        user.changePassword(passwordEncoder.encode(request.newPassword()));
        userRepository.save(user);

        sessionStore.revokeAllForUser(user.getId());
        log.info("비밀번호 재설정 완료: userId={}", user.getId());
        return new PasswordResetResponse(true);
    }
}
