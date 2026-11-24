package com.connect11.server.domain.user.service;

import com.connect11.server.domain.user.entity.User;
import com.connect11.server.domain.user.repository.UserRepository;
import com.connect11.server.global.config.AppProperties;
import com.connect11.server.global.security.SecretHasher;
import com.connect11.server.global.util.EmailNormalizer;
import com.connect11.server.global.util.PasswordPolicy;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class AdminAccountInitializer implements ApplicationRunner {

    static final int MAX_NAME_LENGTH = 50;

    private final AppProperties properties;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void run(ApplicationArguments args) {
        AppProperties.Admin admin = properties.admin();
        if (admin == null || isBlank(admin.email()) || isBlank(admin.password())) {
            return;
        }

        String email = EmailNormalizer.normalize(admin.email());
        if (!email.contains("@") || email.length() > 255) {
            throw new IllegalStateException("ADMIN_EMAIL 형식이 올바르지 않습니다.");
        }
        if (!PasswordPolicy.isValid(admin.password())) {
            throw new IllegalStateException("ADMIN_PASSWORD가 비밀번호 정책(10~72자, 영문자와 숫자 포함)을 충족하지 않습니다.");
        }
        String name = isBlank(admin.name()) ? "관리자" : admin.name().trim();
        if (name.length() > MAX_NAME_LENGTH) {
            throw new IllegalStateException("ADMIN_NAME은 50자 이하여야 합니다.");
        }

        if (userRepository.existsByEmail(email)) {
            log.info("관리자 시드 건너뜀: 이미 존재하는 계정입니다. email={}", EmailNormalizer.mask(email));
            return;
        }
        try {
            userRepository.saveAndFlush(User.createAdmin(
                    email, passwordEncoder.encode(admin.password()), name, adminStudentNumber(email)));
            log.info("관리자 계정을 생성했습니다. email={} (시드 후 ADMIN_PASSWORD를 환경변수에서 제거하세요)",
                    EmailNormalizer.mask(email));
        } catch (DataIntegrityViolationException e) {
            log.info("관리자 시드 건너뜀: 다른 인스턴스가 먼저 생성했습니다.");
        }
    }

    static String adminStudentNumber(String email) {
        return "ADMIN-" + SecretHasher.sha256(email).substring(0, 12);
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
