package com.connect11.server.domain.auth.controller;

import com.connect11.server.domain.auth.dto.request.PasswordResetRequest;
import com.connect11.server.domain.auth.dto.response.PasswordResetResponse;
import com.connect11.server.domain.auth.service.PasswordResetService;
import com.connect11.server.global.common.ApiResponse;
import com.connect11.server.global.common.ApiSpec;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/password")
@RequiredArgsConstructor
public class PasswordResetController {

    private static final String BEARER_PREFIX = "Bearer ";

    private final PasswordResetService passwordResetService;

    @PostMapping("/reset")
    public ApiResponse<PasswordResetResponse> reset(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization,
            @Valid @RequestBody PasswordResetRequest request) {
        return ApiResponse.ok(ApiSpec.PASSWORD_RESET,
                passwordResetService.reset(extractBearer(authorization), request));
    }

    private static String extractBearer(String header) {
        if (header == null || !header.regionMatches(true, 0, BEARER_PREFIX, 0, BEARER_PREFIX.length())) {
            return null;
        }
        return header.substring(BEARER_PREFIX.length()).trim();
    }
}
