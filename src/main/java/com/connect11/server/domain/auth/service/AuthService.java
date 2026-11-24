package com.connect11.server.domain.auth.service;

import com.connect11.server.domain.auth.dto.request.LoginRequest;
import com.connect11.server.domain.auth.dto.response.LoginResponse;
import com.connect11.server.domain.auth.dto.response.TokenRefreshResponse;

public interface AuthService {

    record LoginResult(LoginResponse body, String refreshToken) {
    }

    record RefreshResult(TokenRefreshResponse body, String refreshToken) {
    }

    LoginResult login(LoginRequest request, String clientIp);

    RefreshResult refresh(String refreshToken);

    void logout(Long userId, String sessionId, String refreshToken);
}
