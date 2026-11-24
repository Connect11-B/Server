package com.connect11.server.domain.auth.service.impl;

import com.connect11.server.domain.auth.dto.request.SignupRequest;
import com.connect11.server.domain.auth.dto.response.SignupResponse;
import com.connect11.server.domain.auth.entity.VerificationPurpose;
import com.connect11.server.domain.auth.entity.VerificationToken;
import com.connect11.server.domain.auth.repository.VerificationTokenStore;
import com.connect11.server.domain.auth.service.SignupService;
import com.connect11.server.domain.user.entity.User;
import com.connect11.server.domain.user.repository.UserRepository;
import com.connect11.server.global.exception.BusinessException;
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

    // 토큰 소비(Redis)와 DB 저장을 한 트랜잭션으로 묶을 수 없으므로 @Transactional은 쓰지 않는다.
    @Override
    public SignupResponse signup(SignupRequest request) {
        String email = EmailNormalizer.normalize(request.email());
        String token = request.signupToken();

        // 1) 토큰 확인 (이메일 귀속·1회용·만료). 이 단계에서는 토큰을 소비하지 않는다.
        VerificationToken saved = tokenStore.find(VerificationPurpose.SIGNUP, token)
                .orElseThrow(() -> new BusinessException(ErrorCode.SIGNUP_TOKEN_INVALID));
        if (!SecretHasher.constantTimeEquals(saved.email(), email)) {
            throw new BusinessException(ErrorCode.SIGNUP_TOKEN_INVALID);
        }
        if (saved.used()) {
            throw new BusinessException(ErrorCode.SIGNUP_TOKEN_ALREADY_USED);
        }
        if (clock.instant().getEpochSecond() >= saved.expiresAtEpochSecond()) {
            throw new BusinessException(ErrorCode.SIGNUP_TOKEN_EXPIRED);
        }

        // 2) 입력 검증. 틀리면 토큰이 남아 있어 사용자가 고쳐서 다시 요청할 수 있다.
        String displayName = request.displayName().trim();
        if (displayName.isEmpty() || displayName.length() > MAX_NAME_LENGTH) {
            throw new BusinessException(ErrorCode.VALIDATION_ERROR);
        }
        if (!PasswordPolicy.isValid(request.password())) {
            throw new BusinessException(ErrorCode.PASSWORD_POLICY_VIOLATION);
        }
        if (userRepository.existsByEmail(email)) {
            throw new BusinessException(ErrorCode.EMAIL_ALREADY_REGISTERED);
        }
        if (userRepository.existsByStudentNumber(request.studentNumber())) {
            throw new BusinessException(ErrorCode.STUDENT_NUMBER_ALREADY_REGISTERED);
        }

        // 3) 토큰을 한 번만 소비한다. 동시에 같은 토큰으로 요청해도 한 쪽만 통과한다.
        if (!tokenStore.markUsed(VerificationPurpose.SIGNUP, token)) {
            throw new BusinessException(ErrorCode.SIGNUP_TOKEN_ALREADY_USED);
        }

        // 4) 권한은 서버가 STUDENT로 고정한다. 동시 가입은 DB UNIQUE 제약이 막는다.
        try {
            User user = userRepository.saveAndFlush(
                    User.createStudent(email, passwordEncoder.encode(request.password()), displayName,
                            request.studentNumber()));
            log.info("회원가입 완료: userId={}", user.getId());
            return SignupResponse.from(user);
        } catch (DataIntegrityViolationException e) {
            // 동시 가입으로 UNIQUE 제약에 걸렸다. 어느 쪽이 겹쳤는지 다시 확인한다.
            throw new BusinessException(userRepository.existsByEmail(email)
                    ? ErrorCode.EMAIL_ALREADY_REGISTERED
                    : ErrorCode.STUDENT_NUMBER_ALREADY_REGISTERED);
        }
    }
}
