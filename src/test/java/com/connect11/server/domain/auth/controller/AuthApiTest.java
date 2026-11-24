package com.connect11.server.domain.auth.controller;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.connect11.server.domain.auth.dto.request.SignupRequest;
import com.connect11.server.domain.auth.dto.response.LoginResponse;
import com.connect11.server.domain.auth.dto.response.PasswordResetResponse;
import com.connect11.server.domain.auth.dto.response.SignupResponse;
import com.connect11.server.domain.auth.dto.response.TokenRefreshResponse;
import com.connect11.server.domain.auth.service.AuthService;
import com.connect11.server.domain.auth.service.PasswordResetService;
import com.connect11.server.domain.auth.service.SignupService;
import com.connect11.server.domain.user.entity.Role;
import com.connect11.server.global.exception.BusinessException;
import com.connect11.server.global.exception.ErrorCode;
import com.connect11.server.global.security.JwtProvider;
import jakarta.servlet.http.Cookie;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

/** 보안 필터 체인·예외 처리기·JSON 직렬화를 거친 응답 형식과 접근 규칙을 검증한다. (Redis 없이 실행) */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AuthApiTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private JwtProvider jwtProvider;

    @MockitoBean
    private SignupService signupService;

    @MockitoBean
    private AuthService authService;

    @MockitoBean
    private PasswordResetService passwordResetService;

    // ---- 회원가입 ----

    private static final String SIGNUP_JSON = """
            {"signupToken":"t","email":"student@school.kr","password":"Example123!","displayName":"예시학생","studentNumber":"20240101"}
            """;

    @Test
    void 회원가입은_비회원이_호출하고_201과_명세_형식으로_응답한다() throws Exception {
        when(signupService.signup(any())).thenReturn(new SignupResponse(1L, "student@school.kr", "예시학생", Role.STUDENT));

        mockMvc.perform(post("/api/v1/auth/signup").contentType(MediaType.APPLICATION_JSON).content(SIGNUP_JSON))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.api.name").value("회원가입"))
                .andExpect(jsonPath("$.api.featureCode").value("SIGNUP"))
                .andExpect(jsonPath("$.data.userId").value(1))
                .andExpect(jsonPath("$.data.role").value("STUDENT"))
                .andExpect(jsonPath("$.data.password").doesNotExist())
                .andExpect(header().doesNotExist("Set-Cookie"));
    }

    @Test
    void 요청에_role을_보내도_서비스에는_전달되지_않는다() throws Exception {
        when(signupService.signup(any())).thenReturn(new SignupResponse(1L, "student@school.kr", "예시학생", Role.STUDENT));

        mockMvc.perform(post("/api/v1/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"signupToken":"t","email":"student@school.kr","password":"Example123!",
                                 "displayName":"예시학생","studentNumber":"20240101","role":"ADMIN","status":"ACTIVE"}
                                """))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.data.role").value("STUDENT"));

        verify(signupService).signup(any());
        org.assertj.core.api.Assertions.assertThat(SignupRequest.class.getRecordComponents())
                .extracting(c -> c.getName())
                .containsExactly("signupToken", "email", "password", "displayName", "studentNumber");
    }

    @Test
    void 회원가입_필수_값이_없으면_400_VALIDATION_ERROR() throws Exception {
        mockMvc.perform(post("/api/v1/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email":"student@school.kr"}
                                """))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.api.featureCode").value("SIGNUP"))
                .andExpect(jsonPath("$.error.code").value("VALIDATION_ERROR"));
    }

    @Test
    void 학번_형식이_틀리면_400() throws Exception {
        for (String bad : new String[]{"", "2024 0101", "ADMIN-0123456789ab", "1".repeat(21), "학번"}) {
            mockMvc.perform(post("/api/v1/auth/signup")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("""
                                    {"signupToken":"t","email":"student@school.kr","password":"Example123!","displayName":"학생","studentNumber":"%s"}
                                    """.formatted(bad)))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.error.code").value("VALIDATION_ERROR"));
        }
    }

    @Test
    void 가입_오류는_명세의_상태와_코드로_내려간다() throws Exception {
        when(signupService.signup(any())).thenThrow(new BusinessException(ErrorCode.SIGNUP_TOKEN_EXPIRED));

        mockMvc.perform(post("/api/v1/auth/signup").contentType(MediaType.APPLICATION_JSON).content(SIGNUP_JSON))
                .andExpect(status().isGone())
                .andExpect(jsonPath("$.error.code").value("SIGNUP_TOKEN_EXPIRED"));
    }

    // ---- 로그인 ----

    @Test
    void 로그인은_access_token을_본문으로_refresh_token을_HttpOnly_쿠키로_내려준다() throws Exception {
        when(authService.login(any(), eq("127.0.0.1"))).thenReturn(new AuthService.LoginResult(
                LoginResponse.of("access", 1800, 1209600, new LoginResponse.UserSummary(1L, "예시학생", Role.STUDENT)),
                "sid.refresh"));

        mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"student@school.kr","password":"Example123!"}
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.api.featureCode").value("AUTH_LOGIN"))
                .andExpect(jsonPath("$.data.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.data.accessToken").value("access"))
                .andExpect(jsonPath("$.data.accessTokenExpiresIn").value(1800))
                .andExpect(jsonPath("$.data.refreshTokenExpiresIn").value(1209600))
                .andExpect(jsonPath("$.data.refreshToken").doesNotExist())
                .andExpect(jsonPath("$.data.user.userId").value(1))
                .andExpect(jsonPath("$.data.user.role").value("STUDENT"))
                .andExpect(header().string("Cache-Control", "no-store"))
                .andExpect(header().string("Set-Cookie", Matchers.allOf(
                        Matchers.startsWith("refresh_token=sid.refresh;"),
                        Matchers.containsString("HttpOnly"),
                        Matchers.containsString("Secure"),
                        Matchers.containsString("SameSite=Strict"),
                        Matchers.containsString("Path=/api/v1/auth"),
                        Matchers.containsString("Max-Age=1209600"))));
    }

    @Test
    void 로그인_실패는_401이고_쿠키를_내려주지_않는다() throws Exception {
        when(authService.login(any(), any())).thenThrow(new BusinessException(ErrorCode.AUTHENTICATION_FAILED));

        mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"student@school.kr","password":"bad"}
                                """))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error.code").value("AUTHENTICATION_FAILED"))
                .andExpect(jsonPath("$.error.message").value("아이디 또는 비밀번호가 올바르지 않습니다."))
                .andExpect(header().doesNotExist("Set-Cookie"));
    }

    @Test
    void 로그인_시도_제한은_429() throws Exception {
        when(authService.login(any(), any())).thenThrow(new BusinessException(ErrorCode.LOGIN_RATE_LIMITED));

        mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"student@school.kr","password":"bad"}
                                """))
                .andExpect(status().isTooManyRequests())
                .andExpect(jsonPath("$.error.code").value("LOGIN_RATE_LIMITED"));
    }

    @Test
    void 아이디나_비밀번호가_공백이면_400() throws Exception {
        mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"  ","password":"Example123!"}
                                """))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error.code").value("VALIDATION_ERROR"));
        mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"student@school.kr","password":"   "}
                                """))
                .andExpect(status().isBadRequest());
    }

    // ---- 토큰 재발급 ----

    @Test
    void 재발급은_쿠키의_refresh_token을_쓰고_새_쿠키를_내려준다() throws Exception {
        when(authService.refresh("sid.old")).thenReturn(new AuthService.RefreshResult(
                TokenRefreshResponse.of("new-access", 1800, 1209600), "sid.new"));

        mockMvc.perform(post("/api/v1/auth/refresh").cookie(new Cookie("refresh_token", "sid.old")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.api.featureCode").value("AUTH_REFRESH"))
                .andExpect(jsonPath("$.data.accessToken").value("new-access"))
                .andExpect(jsonPath("$.data.refreshToken").doesNotExist())
                .andExpect(header().string("Cache-Control", "no-store"))
                .andExpect(header().string("Set-Cookie", Matchers.allOf(
                        Matchers.startsWith("refresh_token=sid.new;"), Matchers.containsString("HttpOnly"))));
    }

    @Test
    void 요청_본문의_refreshToken은_무시한다() throws Exception {
        when(authService.refresh(null)).thenThrow(new BusinessException(ErrorCode.UNAUTHENTICATED));

        mockMvc.perform(post("/api/v1/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"refreshToken":"sid.from-body"}
                                """))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error.code").value("UNAUTHENTICATED"));
        verify(authService, never()).refresh("sid.from-body");
    }

    @Test
    void 쿠키가_없으면_401_UNAUTHENTICATED이고_쿠키를_건드리지_않는다() throws Exception {
        when(authService.refresh(null)).thenThrow(new BusinessException(ErrorCode.UNAUTHENTICATED));

        mockMvc.perform(post("/api/v1/auth/refresh"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.api.featureCode").value("AUTH_REFRESH"))
                .andExpect(jsonPath("$.error.code").value("UNAUTHENTICATED"))
                .andExpect(header().doesNotExist("Set-Cookie"));
    }

    @Test
    void 폐기된_토큰은_401_REFRESH_TOKEN_REVOKED이고_쿠키를_지운다() throws Exception {
        when(authService.refresh("sid.old")).thenThrow(new BusinessException(ErrorCode.REFRESH_TOKEN_REVOKED));

        mockMvc.perform(post("/api/v1/auth/refresh").cookie(new Cookie("refresh_token", "sid.old")))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error.code").value("REFRESH_TOKEN_REVOKED"))
                .andExpect(header().string("Set-Cookie", Matchers.allOf(
                        Matchers.startsWith("refresh_token=;"), Matchers.containsString("Max-Age=0"))));
    }

    @Test
    void 비활성_계정이면_403이고_쿠키를_지운다() throws Exception {
        when(authService.refresh("sid.old")).thenThrow(new BusinessException(ErrorCode.ACCOUNT_INACTIVE));

        mockMvc.perform(post("/api/v1/auth/refresh").cookie(new Cookie("refresh_token", "sid.old")))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error.code").value("ACCOUNT_INACTIVE"))
                .andExpect(header().string("Set-Cookie", Matchers.containsString("Max-Age=0")));
    }

    // ---- 로그아웃 ----

    @Test
    void 로그아웃은_access_token_없이는_401() throws Exception {
        mockMvc.perform(post("/api/v1/auth/logout").cookie(new Cookie("refresh_token", "sid.secret")))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.api.featureCode").value("LOGOUT"))
                .andExpect(jsonPath("$.error.code").value("UNAUTHENTICATED"));
        verify(authService, never()).logout(any(), any(), any());
    }

    @Test
    void 잘못된_access_token으로_로그아웃하면_401() throws Exception {
        mockMvc.perform(post("/api/v1/auth/logout").header("Authorization", "Bearer not.a.jwt"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void 학생과_관리자_모두_로그아웃할_수_있고_204_본문_없음_쿠키는_삭제() throws Exception {
        String student = jwtProvider.createAccessToken(1L, Role.STUDENT, "sid-1");
        String admin = jwtProvider.createAccessToken(2L, Role.ADMIN, "sid-2");

        mockMvc.perform(post("/api/v1/auth/logout")
                        .header("Authorization", "Bearer " + student)
                        .cookie(new Cookie("refresh_token", "sid-1.secret")))
                .andExpect(status().isNoContent())
                .andExpect(content().string(""))
                .andExpect(header().string("Set-Cookie", Matchers.containsString("Max-Age=0")));
        mockMvc.perform(post("/api/v1/auth/logout")
                        .header("Authorization", "Bearer " + admin)
                        .cookie(new Cookie("refresh_token", "sid-2.secret")))
                .andExpect(status().isNoContent());

        verify(authService).logout(1L, "sid-1", "sid-1.secret");
        verify(authService).logout(2L, "sid-2", "sid-2.secret");
    }

    @Test
    void 쿠키가_없어도_로그아웃은_access_token의_세션으로_처리한다() throws Exception {
        String student = jwtProvider.createAccessToken(1L, Role.STUDENT, "sid-1");

        mockMvc.perform(post("/api/v1/auth/logout").header("Authorization", "Bearer " + student))
                .andExpect(status().isNoContent());

        verify(authService).logout(1L, "sid-1", null);
    }

    @Test
    void 다른_사용자의_refresh_token이면_401_REFRESH_TOKEN_INVALID() throws Exception {
        String student = jwtProvider.createAccessToken(1L, Role.STUDENT, "sid-1");
        org.mockito.Mockito.doThrow(new BusinessException(ErrorCode.REFRESH_TOKEN_INVALID))
                .when(authService).logout(eq(1L), eq("sid-1"), eq("sid-9.secret"));

        mockMvc.perform(post("/api/v1/auth/logout")
                        .header("Authorization", "Bearer " + student)
                        .cookie(new Cookie("refresh_token", "sid-9.secret")))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error.code").value("REFRESH_TOKEN_INVALID"));
    }

    // ---- 비밀번호 재설정 ----

    @Test
    void 재설정은_Authorization_Bearer로_받은_토큰을_서비스에_넘긴다() throws Exception {
        when(passwordResetService.reset(eq("reset-token"), any())).thenReturn(new PasswordResetResponse(true));

        mockMvc.perform(post("/api/v1/password/reset")
                        .header("Authorization", "Bearer reset-token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"newPassword":"NewPassword123!"}
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.api.featureCode").value("PASSWORD_RESET"))
                .andExpect(jsonPath("$.data.passwordUpdated").value(true));
    }

    @Test
    void 재설정_토큰이_없으면_401_RESET_TOKEN_INVALID() throws Exception {
        when(passwordResetService.reset(eq(null), any()))
                .thenThrow(new BusinessException(ErrorCode.RESET_TOKEN_INVALID));

        mockMvc.perform(post("/api/v1/password/reset")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"newPassword":"NewPassword123!"}
                                """))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error.code").value("RESET_TOKEN_INVALID"));
    }

    @Test
    void 재설정_본문에_newPassword가_없으면_400() throws Exception {
        mockMvc.perform(post("/api/v1/password/reset")
                        .header("Authorization", "Bearer reset-token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error.code").value("VALIDATION_ERROR"));
    }
}
