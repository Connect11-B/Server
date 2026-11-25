package com.connect11.server.global.common;

import lombok.Getter;

@Getter
public class ApiResponse<T> {

    private final ApiInfo api;
    private final T data;

    private ApiResponse(CustomResponseKind kind, T data) {
        this.api = new ApiInfo(kind.getName(), kind.getFeatureCode());
        this.data = data;
    }

    public static <T> ApiResponse<T> ok(
            CustomResponseKind kind
    ) {
        return new ApiResponse<>(kind, null);
    }

    public static <T> ApiResponse<T> ok(
            CustomResponseKind kind,
            T data
    ) {
        return new ApiResponse<>(kind, data);
    }
}
