package com.connect11.server.global.common;

import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
public class ErrorResponse {

    private final ApiInfo api;
    private final ErrorInfo error;
    private final OffsetDateTime timestamp;

    private ErrorResponse(CustomResponseKind kind, CustomErrorCode errorCode, String message) {
        this.api = new ApiInfo(
                kind.getName(),
                kind.getFeatureCode()
        );
        this.error = new ErrorInfo(
                errorCode.getErrorCode(),
                message
        );
        this.timestamp = OffsetDateTime.now(
                ZoneId.of("Asia/Seoul")
        ).truncatedTo(ChronoUnit.SECONDS);
    }

    public static ErrorResponse fail(
            CustomResponseKind kind,
            CustomErrorCode errorCode
    ) {
        return fail(kind, errorCode, errorCode.getMessage());
    }

    public static ErrorResponse fail(
            CustomResponseKind kind,
            CustomErrorCode errorCode,
            String message
    ) {
        return new ErrorResponse(kind, errorCode, message);
    }

    @Getter
    @RequiredArgsConstructor
    public static class ErrorInfo {
        private final String code;
        private final String message;
    }
}
