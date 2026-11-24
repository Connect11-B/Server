package com.connect11.server.domain.auth.dto.response;

import com.connect11.server.domain.user.entity.Role;

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
