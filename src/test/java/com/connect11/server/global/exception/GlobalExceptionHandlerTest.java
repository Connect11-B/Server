package com.connect11.server.global.exception;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.connect11.server.domain.auth.exception.AuthErrorCode;
import com.connect11.server.domain.auth.repository.RefreshSessionStore;
import com.connect11.server.domain.auth.service.AuthService;
import com.connect11.server.domain.user.entity.Role;
import com.connect11.server.global.security.JwtProvider;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class GlobalExceptionHandlerTest {

    private static final String UUID_PATTERN = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private JwtProvider jwtProvider;

    @MockitoBean
    private AuthService authService;

    @MockitoBean
    private RefreshSessionStore sessionStore;

    @BeforeEach
    void activeSessions() {
        when(sessionStore.isActive(any(), any())).thenReturn(true);
    }

    private String studentToken() {
        return "Bearer " + jwtProvider.createAccessToken(1L, Role.STUDENT, "sid-1");
    }

    @Test
    void 업무_예외는_X_Request_ID와_명세_형식으로_응답한다() throws Exception {
        when(authService.login(any(), any())).thenThrow(new CustomException(AuthErrorCode.LOGIN_RATE_LIMITED));

        mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"student@school.kr","password":"Example123!"}
                                """))
                .andExpect(status().isTooManyRequests())
                .andExpect(header().string("X-Request-ID", Matchers.matchesPattern(UUID_PATTERN)))
                .andExpect(header().doesNotExist("WWW-Authenticate"))
                .andExpect(jsonPath("$.api.name").value("로그인"))
                .andExpect(jsonPath("$.api.featureCode").value("AUTH_LOGIN"))
                .andExpect(jsonPath("$.error.code").value("LOGIN_RATE_LIMITED"))
                .andExpect(jsonPath("$.error.message").value("요청이 너무 많습니다. 잠시 후 다시 시도해 주세요."))
                .andExpect(jsonPath("$.timestamp").value(Matchers.matchesPattern(
                        "\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}\\+09:00")));
    }

    @Test
    void 메시지를_지정한_예외는_그_메시지로_응답한다() throws Exception {
        when(authService.login(any(), any()))
                .thenThrow(new CustomException(AuthErrorCode.ACCOUNT_INACTIVE, "관리자에게 문의해 주세요."));

        mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"student@school.kr","password":"Example123!"}
                                """))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error.code").value("ACCOUNT_INACTIVE"))
                .andExpect(jsonPath("$.error.message").value("관리자에게 문의해 주세요."));
    }

    @Test
    void 인증_실패_401에는_WWW_Authenticate_Bearer가_붙는다() throws Exception {
        mockMvc.perform(get("/api/v1/rentals/me"))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string("WWW-Authenticate", "Bearer"))
                .andExpect(header().string("X-Request-ID", Matchers.matchesPattern(UUID_PATTERN)))
                .andExpect(jsonPath("$.api.featureCode").value("UNKNOWN"))
                .andExpect(jsonPath("$.error.code").value("UNAUTHENTICATED"));
    }

    @Test
    void 요청마다_다른_요청_ID를_쓴다() throws Exception {
        String first = mockMvc.perform(get("/api/v1/rentals/me")).andReturn().getResponse().getHeader("X-Request-ID");
        String second = mockMvc.perform(get("/api/v1/rentals/me")).andReturn().getResponse().getHeader("X-Request-ID");

        org.assertj.core.api.Assertions.assertThat(first).isNotEqualTo(second);
    }

    @Test
    void 없는_경로는_404_NOT_FOUND() throws Exception {
        mockMvc.perform(get("/api/v1/rentals/me").header("Authorization", studentToken()))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error.code").value("NOT_FOUND"))
                .andExpect(jsonPath("$.error.message").value("요청한 정보를 찾을 수 없습니다."));
    }

    @Test
    void 지원하지_않는_메서드는_405_METHOD_NOT_ALLOWED() throws Exception {
        mockMvc.perform(get("/api/v1/auth/login").header("Authorization", studentToken()))
                .andExpect(status().isMethodNotAllowed())
                .andExpect(header().exists("Allow"))
                .andExpect(jsonPath("$.error.code").value("METHOD_NOT_ALLOWED"));
    }

    @Test
    void 지원하지_않는_요청_형식은_415_UNSUPPORTED_MEDIA_TYPE() throws Exception {
        mockMvc.perform(post("/api/v1/auth/login").contentType(MediaType.TEXT_PLAIN).content("hi"))
                .andExpect(status().isUnsupportedMediaType())
                .andExpect(jsonPath("$.api.featureCode").value("AUTH_LOGIN"))
                .andExpect(jsonPath("$.error.code").value("UNSUPPORTED_MEDIA_TYPE"));
    }

    @Test
    void 요청_검증_실패는_400_VALIDATION_ERROR() throws Exception {
        mockMvc.perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error.code").value("VALIDATION_ERROR"));
    }
}
