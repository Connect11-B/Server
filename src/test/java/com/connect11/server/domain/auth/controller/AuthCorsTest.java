package com.connect11.server.domain.auth.controller;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.connect11.server.domain.auth.dto.response.TokenRefreshResponse;
import com.connect11.server.domain.auth.service.AuthService;
import com.connect11.server.domain.auth.service.PasswordResetService;
import com.connect11.server.domain.auth.service.SignupService;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

/** refresh token을 쿠키로 쓰므로, 허용 목록에 없는 Origin의 요청이 서비스까지 닿지 않는지 확인한다. */
@SpringBootTest(properties = "app.cors.allowed-origins=http://localhost:5173, https://village.school.kr")
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AuthCorsTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private SignupService signupService;

    @MockitoBean
    private AuthService authService;

    @MockitoBean
    private PasswordResetService passwordResetService;

    @Test
    void 허용_목록에_없는_Origin의_재발급_요청은_403이고_서비스가_호출되지_않는다() throws Exception {
        mockMvc.perform(post("/api/v1/auth/refresh")
                        .header("Origin", "https://evil.example")
                        .cookie(new Cookie("refresh_token", "sid.old")))
                .andExpect(status().isForbidden())
                .andExpect(header().doesNotExist("Set-Cookie"));

        verify(authService, never()).refresh(any());
    }

    @Test
    void Origin이_null인_요청도_거부한다() throws Exception {
        mockMvc.perform(post("/api/v1/auth/refresh")
                        .header("Origin", "null")
                        .cookie(new Cookie("refresh_token", "sid.old")))
                .andExpect(status().isForbidden());

        verify(authService, never()).refresh(any());
    }

    @Test
    void 허용된_Origin은_자격_증명을_포함해_통과한다() throws Exception {
        when(authService.refresh("sid.old")).thenReturn(new AuthService.RefreshResult(
                TokenRefreshResponse.of("new-access", 1800, 1209600), "sid.new"));

        mockMvc.perform(post("/api/v1/auth/refresh")
                        .header("Origin", "http://localhost:5173")
                        .cookie(new Cookie("refresh_token", "sid.old")))
                .andExpect(status().isOk())
                .andExpect(header().string("Access-Control-Allow-Origin", "http://localhost:5173"))
                .andExpect(header().string("Access-Control-Allow-Credentials", "true"));
    }

    @Test
    void 프리플라이트는_허용된_Origin에만_응답한다() throws Exception {
        mockMvc.perform(options("/api/v1/auth/refresh")
                        .header("Origin", "https://village.school.kr")
                        .header("Access-Control-Request-Method", "POST"))
                .andExpect(status().isOk())
                .andExpect(header().string("Access-Control-Allow-Origin", "https://village.school.kr"))
                .andExpect(header().string("Access-Control-Allow-Credentials", "true"));
        mockMvc.perform(options("/api/v1/auth/refresh")
                        .header("Origin", "https://evil.example")
                        .header("Access-Control-Request-Method", "POST"))
                .andExpect(status().isForbidden());
    }
}
