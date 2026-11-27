package com.connect11.server.global.exception;

import com.connect11.server.global.common.ApiSpec;
import com.connect11.server.global.common.CustomErrorCode;
import com.connect11.server.global.common.ErrorResponse;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Component;

@Component
public class ErrorResponseFactory {

    public ErrorResponse create(HttpServletRequest request, CustomErrorCode code) {
        return create(request, code, code.getMessage());
    }

    public ErrorResponse create(HttpServletRequest request, CustomErrorCode code, String message) {
        return ErrorResponse.fail(ApiSpec.find(request.getMethod(), request.getRequestURI()), code, message);
    }
}
