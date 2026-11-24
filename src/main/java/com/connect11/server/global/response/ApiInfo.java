package com.connect11.server.global.response;

public record ApiInfo(String name, String featureCode) {

    public static ApiInfo of(ApiSpec spec) {
        return new ApiInfo(spec.getName(), spec.name());
    }

    public static ApiInfo unknown() {
        return new ApiInfo("알 수 없는 API", "UNKNOWN");
    }
}
