package com.connect11.server.domain.auth.controller;

import com.connect11.server.domain.auth.dto.request.LoginRequest;
import com.connect11.server.domain.auth.dto.request.SignupRequest;
import com.connect11.server.domain.auth.dto.response.LoginResponse;
import com.connect11.server.domain.auth.dto.response.SignupResponse;
import com.connect11.server.domain.auth.dto.response.TokenRefreshResponse;
import com.connect11.server.domain.auth.service.AuthService;
import com.connect11.server.domain.auth.service.SignupService;
import com.connect11.server.global.exception.BusinessException;
import com.connect11.server.global.exception.ErrorCode;
import com.connect11.server.global.response.ApiResponse;
import com.connect11.server.global.response.ApiSpec;
import com.connect11.server.global.security.AuthUser;
import com.connect11.server.global.security.RefreshTokenCookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import java.util.Set;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/**
 * access token은 응답 본문(프론트가 메모리에 보관), refresh token은 HttpOnly 쿠키로 주고받는다.
 * 교차 출처 요청은 CORS 설정의 허용 Origin 목록으로 걸러지고, 쿠키는 SameSite 속성으로 한 번 더 제한된다.
 */
@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private static final Set<ErrorCode> CLEAR_COOKIE_ON = Set.of(
            ErrorCode.REFRESH_TOKEN_INVALID, ErrorCode.REFRESH_TOKEN_EXPIRED,
            ErrorCode.REFRESH_TOKEN_REVOKED, ErrorCode.ACCOUNT_INACTIVE);

    private final SignupService signupService;
    private final AuthService authService;
    private final RefreshTokenCookie refreshCookie;

    @PostMapping("/signup")
    @ResponseStatus(HttpStatus.CREATED)
    public ApiResponse<SignupResponse> signup(@Valid @RequestBody SignupRequest request) {
        return ApiResponse.of(ApiSpec.SIGNUP, signupService.signup(request));
    }

    @PostMapping("/login")
    public ApiResponse<LoginResponse> login(@Valid @RequestBody LoginRequest request,
                                            HttpServletRequest http, HttpServletResponse response) {
        // X-Forwarded-For는 클라이언트가 조작할 수 있으므로 직접 연결된 주소만 쓴다.
        AuthService.LoginResult result = authService.login(request, http.getRemoteAddr());
        noStore(response);
        response.addHeader(HttpHeaders.SET_COOKIE, refreshCookie.issue(result.refreshToken()).toString());
        return ApiResponse.of(ApiSpec.AUTH_LOGIN, result.body());
    }

    @PostMapping("/refresh")
    public ApiResponse<TokenRefreshResponse> refresh(HttpServletRequest http, HttpServletResponse response) {
        AuthService.RefreshResult result;
        try {
            result = authService.refresh(refreshCookie.read(http).orElse(null));
        } catch (BusinessException e) {
            // 쓸 수 없는 refresh token은 브라우저에 남겨 두지 않는다.
            if (CLEAR_COOKIE_ON.contains(e.getErrorCode())) {
                response.addHeader(HttpHeaders.SET_COOKIE, refreshCookie.clear().toString());
            }
            throw e;
        }
        noStore(response);
        response.addHeader(HttpHeaders.SET_COOKIE, refreshCookie.issue(result.refreshToken()).toString());
        return ApiResponse.of(ApiSpec.AUTH_REFRESH, result.body());
    }

    @PostMapping("/logout")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void logout(@AuthenticationPrincipal AuthUser authUser, HttpServletRequest http,
                       HttpServletResponse response) {
        // 결과와 상관없이 쿠키는 지운다.
        response.addHeader(HttpHeaders.SET_COOKIE, refreshCookie.clear().toString());
        authService.logout(authUser.userId(), authUser.sessionId(), refreshCookie.read(http).orElse(null));
    }

    private static void noStore(HttpServletResponse response) {
        response.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
    }
}
