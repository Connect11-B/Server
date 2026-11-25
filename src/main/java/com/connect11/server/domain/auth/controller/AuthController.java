package com.connect11.server.domain.auth.controller;

import com.connect11.server.domain.auth.dto.request.LoginRequest;
import com.connect11.server.domain.auth.dto.request.SignupRequest;
import com.connect11.server.domain.auth.dto.response.LoginResponse;
import com.connect11.server.domain.auth.dto.response.SignupResponse;
import com.connect11.server.domain.auth.dto.response.TokenRefreshResponse;
import com.connect11.server.domain.auth.exception.AuthErrorCode;
import com.connect11.server.domain.auth.service.AuthService;
import com.connect11.server.domain.auth.service.SignupService;
import com.connect11.server.global.common.ApiResponse;
import com.connect11.server.global.common.ApiSpec;
import com.connect11.server.global.common.CustomErrorCode;
import com.connect11.server.global.exception.BusinessException;
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

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private static final Set<CustomErrorCode> CLEAR_COOKIE_ON = Set.of(
            AuthErrorCode.REFRESH_TOKEN_INVALID, AuthErrorCode.REFRESH_TOKEN_EXPIRED,
            AuthErrorCode.REFRESH_TOKEN_REVOKED, AuthErrorCode.ACCOUNT_INACTIVE);

    private final SignupService signupService;
    private final AuthService authService;
    private final RefreshTokenCookie refreshCookie;

    @PostMapping("/signup")
    @ResponseStatus(HttpStatus.CREATED)
    public ApiResponse<SignupResponse> signup(@Valid @RequestBody SignupRequest request) {
        return ApiResponse.ok(ApiSpec.SIGNUP, signupService.signup(request));
    }

    @PostMapping("/login")
    public ApiResponse<LoginResponse> login(@Valid @RequestBody LoginRequest request,
                                            HttpServletRequest http, HttpServletResponse response) {
        AuthService.LoginResult result = authService.login(request, http.getRemoteAddr());
        noStore(response);
        response.addHeader(HttpHeaders.SET_COOKIE, refreshCookie.issue(result.refreshToken()).toString());
        return ApiResponse.ok(ApiSpec.AUTH_LOGIN, result.body());
    }

    @PostMapping("/refresh")
    public ApiResponse<TokenRefreshResponse> refresh(HttpServletRequest http, HttpServletResponse response) {
        AuthService.RefreshResult result;
        try {
            result = authService.refresh(refreshCookie.read(http).orElse(null));
        } catch (BusinessException e) {
            if (CLEAR_COOKIE_ON.contains(e.getErrorCode())) {
                response.addHeader(HttpHeaders.SET_COOKIE, refreshCookie.clear().toString());
            }
            throw e;
        }
        noStore(response);
        response.addHeader(HttpHeaders.SET_COOKIE, refreshCookie.issue(result.refreshToken()).toString());
        return ApiResponse.ok(ApiSpec.AUTH_REFRESH, result.body());
    }

    @PostMapping("/logout")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void logout(@AuthenticationPrincipal AuthUser authUser, HttpServletRequest http,
                       HttpServletResponse response) {
        response.addHeader(HttpHeaders.SET_COOKIE, refreshCookie.clear().toString());
        authService.logout(authUser.userId(), authUser.sessionId(), refreshCookie.read(http).orElse(null));
    }

    private static void noStore(HttpServletResponse response) {
        response.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
    }
}
