package com.connect11.server.global.response;

public record ApiResponse<T>(ApiInfo api, T data) {

    public static <T> ApiResponse<T> of(ApiSpec spec, T data) {
        return new ApiResponse<>(ApiInfo.of(spec), data);
    }
}