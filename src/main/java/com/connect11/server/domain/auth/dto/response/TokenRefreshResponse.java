package com.connect11.server.domain.auth.dto.response;

public record TokenRefreshResponse(
        String tokenType,
        String accessToken,
        long accessTokenExpiresIn,
        long refreshTokenExpiresIn) {

    public static TokenRefreshResponse of(String accessToken, long accessTtl, long refreshTtl) {
        return new TokenRefreshResponse("Bearer", accessToken, accessTtl, refreshTtl);
    }
}
