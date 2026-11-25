package com.connect11.server.domain.auth.controller;

import com.connect11.server.domain.auth.dto.request.*;
import com.connect11.server.domain.auth.dto.response.*;
import com.connect11.server.domain.auth.service.EmailVerificationService;
import com.connect11.server.global.common.ApiResponse;
import com.connect11.server.global.common.ApiSpec;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth/email")
@RequiredArgsConstructor
public class EmailVerificationController {

    private final EmailVerificationService emailVerificationService;

    @PostMapping("/send")
    public ApiResponse<EmailSendResponse> send(@Valid @RequestBody EmailSendRequest request,
                                               HttpServletRequest http) {
        return ApiResponse.ok(ApiSpec.EMAIL_SEND, emailVerificationService.send(request, http.getRemoteAddr()));
    }

    @PostMapping("/verify")
    public ApiResponse<EmailVerifyResponse> verify(@Valid @RequestBody EmailVerifyRequest request) {
        return ApiResponse.ok(ApiSpec.EMAIL_VERIFY, emailVerificationService.verify(request));
    }
}
