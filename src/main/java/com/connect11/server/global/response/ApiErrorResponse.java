package com.connect11.server.global.response;

import com.connect11.server.global.exception.ErrorCode;
import jakarta.servlet.http.HttpServletRequest;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;

public record ApiErrorResponse(ApiInfo api, ErrorBody error, String timestamp) {

    private static final ZoneId KST = ZoneId.of("Asia/Seoul");

    public record ErrorBody(String code, String message) {
    }

    public static ApiErrorResponse of(HttpServletRequest request, ErrorCode errorCode) {
        String now = OffsetDateTime.now(KST)
                .truncatedTo(ChronoUnit.SECONDS)
                .format(DateTimeFormatter.ISO_OFFSET_DATE_TIME);
        return new ApiErrorResponse(
                ApiSpec.find(request.getMethod(), request.getRequestURI()),
                new ErrorBody(errorCode.name(), errorCode.getMessage()),
                now);
    }
}
