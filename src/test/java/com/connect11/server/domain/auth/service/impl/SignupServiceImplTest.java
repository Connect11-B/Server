package com.connect11.server.domain.auth.service.impl;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.connect11.server.domain.auth.dto.request.SignupRequest;
import com.connect11.server.domain.auth.dto.response.SignupResponse;
import com.connect11.server.domain.auth.entity.VerificationPurpose;
import com.connect11.server.domain.auth.entity.VerificationToken;
import com.connect11.server.domain.auth.repository.VerificationTokenStore;
import com.connect11.server.domain.user.entity.Role;
import com.connect11.server.domain.user.entity.User;
import com.connect11.server.domain.user.repository.UserRepository;
import com.connect11.server.global.exception.BusinessException;
import com.connect11.server.global.exception.ErrorCode;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

class SignupServiceImplTest {

    private static final Instant NOW = Instant.parse("2026-11-24T00:00:00Z");
    private static final String TOKEN = "signup-token";
    private static final String EMAIL = "student@school.kr";
    private static final String PASSWORD = "Example123!";

    private VerificationTokenStore tokenStore;
    private UserRepository userRepository;
    private PasswordEncoder encoder;
    private SignupServiceImpl service;

    @BeforeEach
    void setUp() {
        tokenStore = mock(VerificationTokenStore.class);
        userRepository = mock(UserRepository.class);
        encoder = new BCryptPasswordEncoder(4);
        service = new SignupServiceImpl(tokenStore, userRepository, encoder, Clock.fixed(NOW, ZoneOffset.UTC));

        when(userRepository.saveAndFlush(any(User.class))).thenAnswer(inv -> inv.getArgument(0));
    }

    private void tokenIs(String email, boolean used, long expiresAt) {
        when(tokenStore.find(VerificationPurpose.SIGNUP, TOKEN)).thenReturn(Optional.of(
                new VerificationToken(VerificationPurpose.SIGNUP, email, expiresAt, used)));
    }

    private void validToken() {
        tokenIs(EMAIL, false, NOW.getEpochSecond() + 300);
        when(tokenStore.markUsed(VerificationPurpose.SIGNUP, TOKEN)).thenReturn(true);
    }

    private static final String STUDENT_NO = "20240101";

    private SignupRequest request(String email, String password, String name) {
        return new SignupRequest(TOKEN, email, password, name, STUDENT_NO);
    }

    private ErrorCode errorOf(ThrowingCallable callable) {
        return ((BusinessException) catchThrowable(callable)).getErrorCode();
    }

    private Throwable catchThrowable(ThrowingCallable callable) {
        return org.assertj.core.api.Assertions.catchThrowable(callable);
    }

    @Test
    void 가입에_성공하면_STUDENT_계정이_만들어지고_비밀번호는_해시로_저장된다() {
        validToken();

        SignupResponse response = service.signup(request(" Student@School.kr ", PASSWORD, "  예시학생 "));

        ArgumentCaptor<User> captor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).saveAndFlush(captor.capture());
        User saved = captor.getValue();
        assertThat(saved.getRole()).isEqualTo(Role.STUDENT);
        assertThat(saved.getEmail()).isEqualTo(EMAIL);
        assertThat(saved.getName()).isEqualTo("예시학생");
        assertThat(saved.getStudentNumber()).isEqualTo(STUDENT_NO);
        assertThat(saved.isActive()).isTrue();
        assertThat(saved.getPasswordHash()).isNotEqualTo(PASSWORD);
        assertThat(encoder.matches(PASSWORD, saved.getPasswordHash())).isTrue();
        assertThat(response.role()).isEqualTo(Role.STUDENT);
        assertThat(response.email()).isEqualTo(EMAIL);
        assertThat(response.displayName()).isEqualTo("예시학생");
        verify(tokenStore).markUsed(VerificationPurpose.SIGNUP, TOKEN);
    }

    @Test
    void 토큰이_없으면_401_SIGNUP_TOKEN_INVALID() {
        when(tokenStore.find(VerificationPurpose.SIGNUP, TOKEN)).thenReturn(Optional.empty());

        assertThat(errorOf(() -> service.signup(request(EMAIL, PASSWORD, "학생"))))
                .isEqualTo(ErrorCode.SIGNUP_TOKEN_INVALID);
        verify(userRepository, never()).saveAndFlush(any());
    }

    @Test
    void 토큰에_귀속된_이메일과_다르면_INVALID이고_토큰은_소비되지_않는다() {
        validToken();

        assertThat(errorOf(() -> service.signup(request("other@school.kr", PASSWORD, "학생"))))
                .isEqualTo(ErrorCode.SIGNUP_TOKEN_INVALID);
        verify(tokenStore, never()).markUsed(any(), any());
        verify(userRepository, never()).saveAndFlush(any());
    }

    @Test
    void 이미_사용된_토큰은_409_ALREADY_USED() {
        tokenIs(EMAIL, true, NOW.getEpochSecond() + 300);

        assertThat(errorOf(() -> service.signup(request(EMAIL, PASSWORD, "학생"))))
                .isEqualTo(ErrorCode.SIGNUP_TOKEN_ALREADY_USED);
        verify(userRepository, never()).saveAndFlush(any());
    }

    @Test
    void 만료된_토큰은_410_EXPIRED() {
        tokenIs(EMAIL, false, NOW.getEpochSecond());

        assertThat(errorOf(() -> service.signup(request(EMAIL, PASSWORD, "학생"))))
                .isEqualTo(ErrorCode.SIGNUP_TOKEN_EXPIRED);
        verify(userRepository, never()).saveAndFlush(any());
    }

    @Test
    void 비밀번호_정책을_어기면_400이고_토큰은_소비되지_않는다() {
        validToken();

        for (String bad : new String[]{"short1A", "onlyletterspassword", "1234567890123", "a1".repeat(37)}) {
            assertThat(errorOf(() -> service.signup(request(EMAIL, bad, "학생"))))
                    .isEqualTo(ErrorCode.PASSWORD_POLICY_VIOLATION);
        }
        verify(tokenStore, never()).markUsed(any(), any());
        verify(userRepository, never()).saveAndFlush(any());
    }

    @Test
    void 이름이_공백뿐이거나_30자를_넘으면_VALIDATION_ERROR() {
        validToken();

        assertThat(errorOf(() -> service.signup(request(EMAIL, PASSWORD, "   ")))).isEqualTo(ErrorCode.VALIDATION_ERROR);
        assertThat(errorOf(() -> service.signup(request(EMAIL, PASSWORD, "가".repeat(31)))))
                .isEqualTo(ErrorCode.VALIDATION_ERROR);
        verify(tokenStore, never()).markUsed(any(), any());
    }

    @Test
    void 이름은_공백_정리_후_30자까지_허용() {
        validToken();

        service.signup(request(EMAIL, PASSWORD, "  " + "가".repeat(30) + "  "));

        verify(userRepository).saveAndFlush(any(User.class));
    }

    @Test
    void 이미_가입된_이메일이면_409이고_토큰은_소비되지_않는다() {
        validToken();
        when(userRepository.existsByEmail(EMAIL)).thenReturn(true);

        assertThat(errorOf(() -> service.signup(request(EMAIL, PASSWORD, "학생"))))
                .isEqualTo(ErrorCode.EMAIL_ALREADY_REGISTERED);
        verify(tokenStore, never()).markUsed(any(), any());
    }

    @Test
    void 이미_등록된_학번이면_409이고_토큰은_소비되지_않는다() {
        validToken();
        when(userRepository.existsByStudentNumber(STUDENT_NO)).thenReturn(true);

        assertThat(errorOf(() -> service.signup(request(EMAIL, PASSWORD, "학생"))))
                .isEqualTo(ErrorCode.STUDENT_NUMBER_ALREADY_REGISTERED);
        verify(tokenStore, never()).markUsed(any(), any());
        verify(userRepository, never()).saveAndFlush(any());
    }

    @Test
    void 동시에_같은_토큰을_쓰면_소비에_실패한_쪽은_ALREADY_USED() {
        tokenIs(EMAIL, false, NOW.getEpochSecond() + 300);
        when(tokenStore.markUsed(VerificationPurpose.SIGNUP, TOKEN)).thenReturn(false);

        assertThat(errorOf(() -> service.signup(request(EMAIL, PASSWORD, "학생"))))
                .isEqualTo(ErrorCode.SIGNUP_TOKEN_ALREADY_USED);
        verify(userRepository, never()).saveAndFlush(any());
    }

    @Test
    void 동시_가입으로_이메일_UNIQUE_제약에_걸리면_409_EMAIL_ALREADY_REGISTERED() {
        validToken();
        when(userRepository.saveAndFlush(any(User.class))).thenThrow(new DataIntegrityViolationException("dup"));
        when(userRepository.existsByEmail(EMAIL)).thenReturn(false, true);   // 사전 확인 때는 없었고 충돌 뒤에는 있다

        assertThatThrownBy(() -> service.signup(request(EMAIL, PASSWORD, "학생")))
                .isInstanceOf(BusinessException.class)
                .extracting(e -> ((BusinessException) e).getErrorCode())
                .isEqualTo(ErrorCode.EMAIL_ALREADY_REGISTERED);
    }

    @Test
    void 동시_가입으로_학번_UNIQUE_제약에_걸리면_409_STUDENT_NUMBER_ALREADY_REGISTERED() {
        validToken();
        when(userRepository.saveAndFlush(any(User.class))).thenThrow(new DataIntegrityViolationException("dup"));

        assertThat(errorOf(() -> service.signup(request(EMAIL, PASSWORD, "학생"))))
                .isEqualTo(ErrorCode.STUDENT_NUMBER_ALREADY_REGISTERED);
    }

    @Test
    void 요청_객체의_toString에는_비밀번호와_토큰이_나오지_않는다() {
        assertThat(request(EMAIL, PASSWORD, "학생").toString()).doesNotContain(PASSWORD).doesNotContain(TOKEN);
    }
}
