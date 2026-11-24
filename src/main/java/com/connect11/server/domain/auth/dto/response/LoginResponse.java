package com.connect11.server.domain.auth.dto.response;

import com.connect11.server.domain.user.entity.Role;

// refresh token은 본문에 없다. HttpOnly 쿠키로만 전달한다.
public record LoginResponse(
        String tokenType,
        String accessToken,
        long accessTokenExpiresIn,
        long refreshTokenExpiresIn,
        UserSummary user) {

    public record UserSummary(Long userId, String name, Role role) {
    }

    public static LoginResponse of(String accessToken, long accessTtl, long refreshTtl, UserSummary user) {
        return new LoginResponse("Bearer", accessToken, accessTtl, refreshTtl, user);
    }
}
