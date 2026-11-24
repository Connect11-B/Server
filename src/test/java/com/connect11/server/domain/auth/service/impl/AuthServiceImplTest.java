package com.connect11.server.domain.auth.service.impl;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.connect11.server.domain.auth.dto.request.LoginRequest;
import com.connect11.server.domain.auth.dto.response.LoginResponse;
import com.connect11.server.domain.auth.service.AuthService.LoginResult;
import com.connect11.server.domain.auth.service.AuthService.RefreshResult;
import com.connect11.server.domain.auth.repository.LoginAttemptLimiter;
import com.connect11.server.domain.auth.repository.RefreshSessionStore;
import com.connect11.server.domain.auth.repository.RefreshSessionStore.Issued;
import com.connect11.server.domain.auth.repository.RefreshSessionStore.RotateResult;
import com.connect11.server.domain.auth.repository.RefreshSessionStore.Status;
import com.connect11.server.domain.user.entity.Role;
import com.connect11.server.domain.user.entity.User;
import com.connect11.server.domain.user.entity.UserStatus;
import com.connect11.server.domain.user.repository.UserRepository;
import com.connect11.server.global.config.AppProperties;
import com.connect11.server.global.exception.BusinessException;
import com.connect11.server.global.exception.ErrorCode;
import com.connect11.server.global.security.AuthUser;
import com.connect11.server.global.security.JwtProvider;
import com.connect11.server.global.security.SecretHasher;
import java.time.Duration;
import java.util.Optional;
import org.assertj.core.api.Assertions;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

class AuthServiceImplTest {

    private static final String EMAIL = "student@school.kr";
    private static final String PASSWORD = "Example123!";
    private static final String IP = "203.0.113.5";
    private static final Duration REFRESH_TTL = Duration.ofSeconds(1209600);

    private UserRepository userRepository;
    private RefreshSessionStore sessionStore;
    private LoginAttemptLimiter limiter;
    private PasswordEncoder encoder;
    private JwtProvider jwtProvider;
    private AuthServiceImpl service;
    private User user;

    @BeforeEach
    void setUp() {
        userRepository = mock(UserRepository.class);
        sessionStore = mock(RefreshSessionStore.class);
        limiter = mock(LoginAttemptLimiter.class);
        encoder = new BCryptPasswordEncoder(4);
        AppProperties props = new AppProperties(
                new AppProperties.Jwt("test-only-jwt-secret-not-for-production-0123456789", 1800),
                new AppProperties.Auth("test-only-pepper-not-for-production", 1209600, true, "Strict"),
                null, null, null);
        jwtProvider = new JwtProvider(props);
        service = new AuthServiceImpl(userRepository, encoder, jwtProvider, sessionStore, limiter,
                new SecretHasher(props), props);

        user = User.createStudent(EMAIL, encoder.encode(PASSWORD), "예시학생", "1234");
        ReflectionTestUtils.setField(user, "id", 1L);

        when(limiter.increment(anyString(), any())).thenReturn(1L);
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(user));
        when(userRepository.findById(1L)).thenReturn(Optional.of(user));
        when(sessionStore.create(eq(1L), any())).thenReturn(new Issued("sid-1", "sid-1.secret"));
    }

    private ErrorCode errorOf(ThrowingCallable callable) {
        return ((BusinessException) Assertions.catchThrowable(callable)).getErrorCode();
    }

    private LoginRequest login(String username, String password) {
        return new LoginRequest(username, password);
    }

    @Test
    void 로그인에_성공하면_토큰과_사용자_정보를_돌려주고_시도_횟수를_초기화한다() {
        LoginResult result = service.login(login(" Student@School.kr ", PASSWORD), IP);
        LoginResponse response = result.body();

        assertThat(result.refreshToken()).isEqualTo("sid-1.secret");
        assertThat(response.toString()).doesNotContain("sid-1.secret");
        assertThat(response.tokenType()).isEqualTo("Bearer");
        assertThat(response.accessTokenExpiresIn()).isEqualTo(1800);
        assertThat(response.refreshTokenExpiresIn()).isEqualTo(1209600);
        assertThat(response.user().userId()).isEqualTo(1L);
        assertThat(response.user().name()).isEqualTo("예시학생");
        assertThat(response.user().role()).isEqualTo(Role.STUDENT);

        AuthUser parsed = jwtProvider.parse(response.accessToken()).orElseThrow();
        assertThat(parsed.userId()).isEqualTo(1L);
        assertThat(parsed.role()).isEqualTo(Role.STUDENT);
        assertThat(parsed.sessionId()).isEqualTo("sid-1");

        verify(sessionStore).create(1L, REFRESH_TTL);
        verify(limiter).reset(anyString());
    }

    @Test
    void 관리자는_ADMIN_권한의_토큰을_받는다() {
        User admin = User.createAdmin("admin@school.kr", encoder.encode(PASSWORD), "관리자", "ADMIN-0123456789ab");
        ReflectionTestUtils.setField(admin, "id", 2L);
        when(userRepository.findByEmail("admin@school.kr")).thenReturn(Optional.of(admin));
        when(sessionStore.create(eq(2L), any())).thenReturn(new Issued("sid-2", "sid-2.secret"));

        LoginResponse response = service.login(login("admin@school.kr", PASSWORD), IP).body();

        assertThat(response.user().role()).isEqualTo(Role.ADMIN);
        assertThat(jwtProvider.parse(response.accessToken()).orElseThrow().role()).isEqualTo(Role.ADMIN);
    }

    @Test
    void 비밀번호가_틀리면_401이고_세션을_만들지_않는다() {
        assertThat(errorOf(() -> service.login(login(EMAIL, "WrongPassword1"), IP)))
                .isEqualTo(ErrorCode.AUTHENTICATION_FAILED);
        verify(sessionStore, never()).create(any(), any());
        verify(limiter, never()).reset(anyString());
    }

    @Test
    void 없는_계정도_같은_401이다() {
        when(userRepository.findByEmail("nobody@school.kr")).thenReturn(Optional.empty());

        assertThat(errorOf(() -> service.login(login("nobody@school.kr", PASSWORD), IP)))
                .isEqualTo(ErrorCode.AUTHENTICATION_FAILED);
    }

    @Test
    void 비활성_계정은_비밀번호가_맞을_때만_403() {
        ReflectionTestUtils.setField(user, "status", UserStatus.INACTIVE);

        assertThat(errorOf(() -> service.login(login(EMAIL, PASSWORD), IP))).isEqualTo(ErrorCode.ACCOUNT_INACTIVE);
        assertThat(errorOf(() -> service.login(login(EMAIL, "WrongPassword1"), IP)))
                .isEqualTo(ErrorCode.AUTHENTICATION_FAILED);
        verify(sessionStore, never()).create(any(), any());
    }

    @Test
    void 시도_횟수를_넘으면_429이고_계정_조회도_하지_않는다() {
        when(limiter.increment(anyString(), any())).thenReturn(6L);

        assertThat(errorOf(() -> service.login(login(EMAIL, PASSWORD), IP))).isEqualTo(ErrorCode.LOGIN_RATE_LIMITED);
        verifyNoInteractions(userRepository);
        verify(sessionStore, never()).create(any(), any());
    }

    @Test
    void 다섯_번째_시도까지는_허용한다() {
        when(limiter.increment(anyString(), any())).thenReturn(5L);

        assertThat(service.login(login(EMAIL, PASSWORD), IP).body().accessToken()).isNotBlank();
    }

    @Test
    void 제한_키에는_이메일과_IP_원문이_들어가지_않는다() {
        service.login(login(EMAIL, PASSWORD), IP);

        ArgumentCaptor<String> key = ArgumentCaptor.forClass(String.class);
        verify(limiter).increment(key.capture(), eq(Duration.ofMinutes(15)));
        assertThat(key.getValue()).doesNotContain("student").doesNotContain(IP);
    }

    @Test
    void 이메일과_IP가_다르면_제한_키도_다르다() {
        service.login(login(EMAIL, PASSWORD), IP);
        service.login(login(EMAIL, PASSWORD), "198.51.100.9");

        ArgumentCaptor<String> key = ArgumentCaptor.forClass(String.class);
        verify(limiter, org.mockito.Mockito.times(2)).increment(key.capture(), any());
        assertThat(key.getAllValues().get(0)).isNotEqualTo(key.getAllValues().get(1));
    }

    @Test
    void 비밀번호가_72바이트를_넘어도_예외_없이_401() {
        assertThat(errorOf(() -> service.login(login(EMAIL, "a".repeat(100)), IP)))
                .isEqualTo(ErrorCode.AUTHENTICATION_FAILED);
    }

    @Test
    void 재발급에_성공하면_새_토큰_쌍을_돌려준다() {
        when(sessionStore.rotate("sid-1.old", REFRESH_TTL))
                .thenReturn(new RotateResult(Status.OK, 1L, "sid-1", "sid-1.new"));

        RefreshResult result = service.refresh("sid-1.old");
        var response = result.body();

        assertThat(result.refreshToken()).isEqualTo("sid-1.new");
        assertThat(response.tokenType()).isEqualTo("Bearer");
        assertThat(response.refreshTokenExpiresIn()).isEqualTo(1209600);
        assertThat(response.accessTokenExpiresIn()).isEqualTo(1800);
        AuthUser parsed = jwtProvider.parse(response.accessToken()).orElseThrow();
        assertThat(parsed.userId()).isEqualTo(1L);
        assertThat(parsed.sessionId()).isEqualTo("sid-1");
    }

    @Test
    void 재발급_때는_DB의_최신_권한으로_access_token을_만든다() {
        ReflectionTestUtils.setField(user, "role", Role.ADMIN);
        when(sessionStore.rotate("sid-1.old", REFRESH_TTL))
                .thenReturn(new RotateResult(Status.OK, 1L, "sid-1", "sid-1.new"));

        var response = service.refresh("sid-1.old").body();

        assertThat(jwtProvider.parse(response.accessToken()).orElseThrow().role()).isEqualTo(Role.ADMIN);
    }

    @Test
    void 재발급_실패_사유가_오류_코드로_매핑된다() {
        assertRefreshError(Status.INVALID, ErrorCode.REFRESH_TOKEN_INVALID);
        assertRefreshError(Status.EXPIRED, ErrorCode.REFRESH_TOKEN_EXPIRED);
        assertRefreshError(Status.REVOKED, ErrorCode.REFRESH_TOKEN_REVOKED);
        assertRefreshError(Status.REUSED, ErrorCode.REFRESH_TOKEN_REVOKED);
        verify(userRepository, never()).findById(any());
    }

    private void assertRefreshError(Status status, ErrorCode expected) {
        when(sessionStore.rotate("sid-1.old", REFRESH_TTL))
                .thenReturn(new RotateResult(status, status == Status.REUSED ? 1L : null, "sid-1", null));
        assertThat(errorOf(() -> service.refresh("sid-1.old"))).isEqualTo(expected);
    }

    @Test
    void 비활성_계정은_재발급을_거부하고_세션을_폐기한다() {
        ReflectionTestUtils.setField(user, "status", UserStatus.INACTIVE);
        when(sessionStore.rotate("sid-1.old", REFRESH_TTL))
                .thenReturn(new RotateResult(Status.OK, 1L, "sid-1", "sid-1.new"));

        assertThat(errorOf(() -> service.refresh("sid-1.old")))
                .isEqualTo(ErrorCode.ACCOUNT_INACTIVE);
        verify(sessionStore).revokeSession("sid-1");
    }

    @Test
    void 계정이_사라진_세션은_INVALID이고_폐기한다() {
        when(userRepository.findById(1L)).thenReturn(Optional.empty());
        when(sessionStore.rotate("sid-1.old", REFRESH_TTL))
                .thenReturn(new RotateResult(Status.OK, 1L, "sid-1", "sid-1.new"));

        assertThat(errorOf(() -> service.refresh("sid-1.old")))
                .isEqualTo(ErrorCode.REFRESH_TOKEN_INVALID);
        verify(sessionStore).revokeSession("sid-1");
    }

    @Test
    void 로그아웃은_요청_사용자의_세션을_폐기한다() {
        when(sessionStore.revokeOwned("sid-1.secret", 1L)).thenReturn(true);

        service.logout(1L, "sid-1", "sid-1.secret");

        verify(sessionStore).revokeOwned("sid-1.secret", 1L);
    }

    @Test
    void 다른_사용자의_토큰이거나_유효하지_않으면_401_REFRESH_TOKEN_INVALID() {
        when(sessionStore.revokeOwned("sid-9.secret", 1L)).thenReturn(false);

        assertThat(errorOf(() -> service.logout(1L, "sid-1", "sid-9.secret")))
                .isEqualTo(ErrorCode.REFRESH_TOKEN_INVALID);
    }

    @Test
    void 쿠키가_없으면_401_UNAUTHENTICATED() {
        assertThat(errorOf(() -> service.refresh(null))).isEqualTo(ErrorCode.UNAUTHENTICATED);
        assertThat(errorOf(() -> service.refresh("  "))).isEqualTo(ErrorCode.UNAUTHENTICATED);
        verifyNoInteractions(sessionStore);
    }

    @Test
    void 쿠키_없이_로그아웃해도_access_token의_세션을_폐기하고_성공한다() {
        service.logout(1L, "sid-1", null);

        verify(sessionStore).revokeSessionOwned("sid-1", 1L);
        verify(sessionStore, never()).revokeOwned(any(), any());
    }
}
