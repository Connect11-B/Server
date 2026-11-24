package com.connect11.server.domain.auth.service;

import com.connect11.server.domain.auth.dto.request.LoginRequest;
import com.connect11.server.domain.auth.dto.response.LoginResponse;
import com.connect11.server.domain.auth.dto.response.TokenRefreshResponse;

public interface AuthService {

    // refresh token 원문은 본문이 아니라 쿠키로 내려가므로 응답 DTO와 따로 돌려준다.
    record LoginResult(LoginResponse body, String refreshToken) {
    }

    record RefreshResult(TokenRefreshResponse body, String refreshToken) {
    }

    LoginResult login(LoginRequest request, String clientIp);

    /** @param refreshToken 쿠키에서 꺼낸 값 (없으면 null) */
    RefreshResult refresh(String refreshToken);

    /**
     * @param sessionId    access token에 들어 있는 세션 ID
     * @param refreshToken 쿠키에서 꺼낸 값 (없으면 null)
     */
    void logout(Long userId, String sessionId, String refreshToken);
}
