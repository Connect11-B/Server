package com.connect11.server.domain.auth.service.impl;

import com.connect11.server.domain.auth.dto.request.SignupRequest;
import com.connect11.server.domain.auth.dto.response.SignupResponse;
import com.connect11.server.domain.auth.entity.VerificationPurpose;
import com.connect11.server.domain.auth.entity.VerificationToken;
import com.connect11.server.domain.auth.exception.AuthErrorCode;
import com.connect11.server.domain.auth.repository.VerificationTokenStore;
import com.connect11.server.domain.auth.service.SignupService;
import com.connect11.server.domain.user.entity.User;
import com.connect11.server.domain.user.repository.UserRepository;
import com.connect11.server.global.exception.CustomException;
import com.connect11.server.global.exception.ErrorCode;
import com.connect11.server.global.security.SecretHasher;
import com.connect11.server.global.util.EmailNormalizer;
import com.connect11.server.global.util.PasswordPolicy;
import java.time.Clock;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class SignupServiceImpl implements SignupService {

    static final int MAX_NAME_LENGTH = 30;

    private final VerificationTokenStore tokenStore;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final Clock clock;

    @Override
    public SignupResponse signup(SignupRequest request) {
        String email = EmailNormalizer.normalize(request.email());
        String token = request.signupToken();

        VerificationToken saved = tokenStore.find(VerificationPurpose.SIGNUP, token)
                .orElseThrow(() -> new CustomException(AuthErrorCode.SIGNUP_TOKEN_INVALID));
        if (!SecretHasher.constantTimeEquals(saved.email(), email)) {
            throw new CustomException(AuthErrorCode.SIGNUP_TOKEN_INVALID);
        }
        if (saved.used()) {
            throw new CustomException(AuthErrorCode.SIGNUP_TOKEN_ALREADY_USED);
        }
        if (clock.instant().getEpochSecond() >= saved.expiresAtEpochSecond()) {
            throw new CustomException(AuthErrorCode.SIGNUP_TOKEN_EXPIRED);
        }

        String displayName = request.displayName().trim();
        if (displayName.isEmpty() || displayName.length() > MAX_NAME_LENGTH) {
            throw new CustomException(ErrorCode.VALIDATION_ERROR);
        }
        if (!PasswordPolicy.isValid(request.password())) {
            throw new CustomException(AuthErrorCode.PASSWORD_POLICY_VIOLATION);
        }
        if (userRepository.existsByEmail(email)) {
            throw new CustomException(AuthErrorCode.EMAIL_ALREADY_REGISTERED);
        }
        if (userRepository.existsByStudentNumber(request.studentNumber())) {
            throw new CustomException(AuthErrorCode.STUDENT_NUMBER_ALREADY_REGISTERED);
        }

        if (!tokenStore.markUsed(VerificationPurpose.SIGNUP, token)) {
            throw new CustomException(AuthErrorCode.SIGNUP_TOKEN_ALREADY_USED);
        }

        try {
            User user = userRepository.saveAndFlush(
                    User.createStudent(email, passwordEncoder.encode(request.password()), displayName,
                            request.studentNumber()));
            log.info("회원가입 완료: userId={}", user.getId());
            return SignupResponse.from(user);
        } catch (DataIntegrityViolationException e) {
            throw new CustomException(userRepository.existsByEmail(email)
                    ? AuthErrorCode.EMAIL_ALREADY_REGISTERED
                    : AuthErrorCode.STUDENT_NUMBER_ALREADY_REGISTERED);
        }
    }
}
