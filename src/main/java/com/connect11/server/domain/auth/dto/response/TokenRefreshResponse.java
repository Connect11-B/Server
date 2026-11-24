package com.connect11.server.domain.auth.dto.response;

// refresh token은 본문에 없다. HttpOnly 쿠키로만 전달한다.
public record TokenRefreshResponse(
        String tokenType,
        String accessToken,
        long accessTokenExpiresIn,
        long refreshTokenExpiresIn) {

    public static TokenRefreshResponse of(String accessToken, long accessTtl, long refreshTtl) {
        return new TokenRefreshResponse("Bearer", accessToken, accessTtl, refreshTtl);
    }
}
