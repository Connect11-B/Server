package com.connect11.server.domain.auth.controller;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.connect11.server.domain.auth.dto.response.EmailSendResponse;
import com.connect11.server.domain.auth.dto.response.EmailVerifyResponse;
import com.connect11.server.domain.auth.entity.VerificationPurpose;
import com.connect11.server.domain.auth.service.EmailVerificationService;
import com.connect11.server.domain.user.entity.Role;
import com.connect11.server.global.exception.BusinessException;
import com.connect11.server.global.exception.ErrorCode;
import com.connect11.server.global.security.JwtProvider;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

/**
 * 실제 보안 필터 체인·예외 처리기·JSON 직렬화를 거쳐 응답 형식을 검증한다.
 * Redis를 쓰는 서비스는 Mock으로 바꿔서 CI에서도 Redis 없이 실행된다.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class EmailVerificationApiTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private JwtProvider jwtProvider;

    @MockitoBean
    private EmailVerificationService emailVerificationService;

    @Test
    void 코드_발송은_비회원도_호출할_수_있고_명세_형식으로_응답한다() throws Exception {
        when(emailVerificationService.send(any())).thenReturn(new EmailSendResponse("vid-1", 600, 60));

        mockMvc.perform(post("/api/v1/auth/email/send")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email":"student@school.kr","purpose":"SIGNUP"}
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.api.name").value("이메일 인증 코드 발송"))
                .andExpect(jsonPath("$.api.featureCode").value("EMAIL_SEND"))
                .andExpect(jsonPath("$.data.verificationId").value("vid-1"))
                .andExpect(jsonPath("$.data.expiresIn").value(600))
                .andExpect(jsonPath("$.data.resendAfter").value(60))
                .andExpect(jsonPath("$.success").doesNotExist());
    }

    @Test
    void 이메일_형식이_틀리면_400_VALIDATION_ERROR() throws Exception {
        mockMvc.perform(post("/api/v1/auth/email/send")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email":"not-an-email","purpose":"SIGNUP"}
                                """))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.api.featureCode").value("EMAIL_SEND"))
                .andExpect(jsonPath("$.error.code").value("VALIDATION_ERROR"))
                .andExpect(jsonPath("$.timestamp").value(Matchers.endsWith("+09:00")));
    }

    @Test
    void 정의되지_않은_purpose나_깨진_JSON은_400_VALIDATION_ERROR() throws Exception {
        mockMvc.perform(post("/api/v1/auth/email/send")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email":"student@school.kr","purpose":"ADMIN"}
                                """))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error.code").value("VALIDATION_ERROR"));

        mockMvc.perform(post("/api/v1/auth/email/send")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{broken"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error.code").value("VALIDATION_ERROR"));
    }

    @Test
    void 코드가_6자리_숫자가_아니면_400() throws Exception {
        mockMvc.perform(post("/api/v1/auth/email/verify")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"verificationId":"vid-1","code":"12ab56"}
                                """))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.api.featureCode").value("EMAIL_VERIFY"))
                .andExpect(jsonPath("$.error.code").value("VALIDATION_ERROR"));
    }

    @Test
    void 비즈니스_예외는_해당_상태코드와_에러코드로_응답한다() throws Exception {
        when(emailVerificationService.send(any())).thenThrow(new BusinessException(ErrorCode.EMAIL_RATE_LIMITED));

        mockMvc.perform(post("/api/v1/auth/email/send")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email":"student@school.kr","purpose":"SIGNUP"}
                                """))
                .andExpect(status().isTooManyRequests())
                .andExpect(jsonPath("$.error.code").value("EMAIL_RATE_LIMITED"))
                .andExpect(jsonPath("$.error.message").value("잠시 후 다시 시도해 주세요."));
    }

    @Test
    void 회원가입_인증_성공시_signupToken만_내려가고_resetToken_필드는_없다() throws Exception {
        when(emailVerificationService.verify(any()))
                .thenReturn(EmailVerifyResponse.of(VerificationPurpose.SIGNUP, "signup-token", 600));

        mockMvc.perform(post("/api/v1/auth/email/verify")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"verificationId":"vid-1","code":"123456"}
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.purpose").value("SIGNUP"))
                .andExpect(jsonPath("$.data.signupToken").value("signup-token"))
                .andExpect(jsonPath("$.data.resetToken").doesNotExist())
                .andExpect(jsonPath("$.data.expiresIn").value(600));
    }

    @Test
    void 처리되지_않은_예외는_500이고_내부_메시지를_노출하지_않는다() throws Exception {
        when(emailVerificationService.send(any())).thenThrow(new IllegalStateException("redis password=secret"));

        mockMvc.perform(post("/api/v1/auth/email/send")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email":"student@school.kr","purpose":"SIGNUP"}
                                """))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.error.code").value("INTERNAL_ERROR"))
                .andExpect(jsonPath("$.error.message").value("서버 오류가 발생했습니다."));
    }

    // ---- 2묶음(권한 규칙) 확인 ----

    @Test
    void 토큰_없이_보호된_API를_호출하면_401_UNAUTHENTICATED() throws Exception {
        mockMvc.perform(get("/api/v1/rentals/me"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error.code").value("UNAUTHENTICATED"))
                .andExpect(jsonPath("$.timestamp").exists());
    }

    @Test
    void 위조된_토큰은_401() throws Exception {
        mockMvc.perform(get("/api/v1/rentals/me").header("Authorization", "Bearer not.a.jwt"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error.code").value("UNAUTHENTICATED"));
    }

    @Test
    void 학생이_관리자_API를_호출하면_403_FORBIDDEN() throws Exception {
        String studentToken = jwtProvider.createAccessToken(1L, Role.STUDENT, "s-1");

        mockMvc.perform(get("/api/v1/admin/rentals").header("Authorization", "Bearer " + studentToken))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error.code").value("FORBIDDEN"));
    }

    @Test
    void 관리자가_학생_전용_API를_호출하면_403() throws Exception {
        String adminToken = jwtProvider.createAccessToken(2L, Role.ADMIN, "s-2");

        mockMvc.perform(post("/api/v1/rentals").header("Authorization", "Bearer " + adminToken)
                        .contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error.code").value("FORBIDDEN"));
    }
}
