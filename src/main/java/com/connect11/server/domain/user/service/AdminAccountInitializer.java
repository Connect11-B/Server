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

/**
 * 명세: ADMIN 계정은 가입 API가 아니라 운영자가 시드로 발급한다.
 * ADMIN_EMAIL, ADMIN_PASSWORD가 설정되어 있고 같은 이메일의 계정이 없을 때만 한 번 생성한다.
 * 이미 있는 계정은 건드리지 않으며(비밀번호도 덮어쓰지 않음), 값이 잘못되면 서버 시작을 실패시킨다.
 */
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
            // 비밀번호 값은 로그·메시지에 남기지 않는다.
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
            // 여러 인스턴스가 동시에 시작해 다른 쪽이 먼저 만든 경우
            log.info("관리자 시드 건너뜀: 다른 인스턴스가 먼저 생성했습니다.");
        }
    }

    // student_number가 NOT NULL·UNIQUE라 관리자에게도 값이 필요하다. 이메일에서 만든 고정 값을 쓴다.
    // 학생 학번은 영문자·숫자만 허용하므로 '-'가 들어간 이 값과 겹칠 수 없다.
    static String adminStudentNumber(String email) {
        return "ADMIN-" + SecretHasher.sha256(email).substring(0, 12);
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
