package com.connect11.server.global.exception;

import com.connect11.server.global.common.CustomErrorCode;
import com.connect11.server.global.common.ErrorResponse;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

@RestControllerAdvice
public class GlobalExceptionHandler extends ResponseEntityExceptionHandler {

    private final ErrorResponseFactory factory;
    private final FailureLogger failureLogger;

    public GlobalExceptionHandler(ErrorResponseFactory factory, FailureLogger failureLogger) {
        this.factory = factory;
        this.failureLogger = failureLogger;
    }

    @ExceptionHandler(BusinessException.class)
    ResponseEntity<ErrorResponse> handleCustomException(BusinessException exception, HttpServletRequest request) {
        return respond(request, exception.getErrorCode(), exception.getMessage());
    }

    @ExceptionHandler(AuthenticationException.class)
    ResponseEntity<ErrorResponse> handleAuthentication(HttpServletRequest request) {
        return respond(request, ErrorCode.UNAUTHENTICATED, ErrorCode.UNAUTHENTICATED.getMessage());
    }

    @ExceptionHandler(AccessDeniedException.class)
    ResponseEntity<ErrorResponse> handleAccessDenied(HttpServletRequest request) {
        return respond(request, ErrorCode.FORBIDDEN, ErrorCode.FORBIDDEN.getMessage());
    }

    @ExceptionHandler(Exception.class)
    ResponseEntity<ErrorResponse> handleUnexpected(Exception exception, HttpServletRequest request) {
        failureLogger.logUnexpected(request, exception);
        return respond(request, ErrorCode.INTERNAL_ERROR, ErrorCode.INTERNAL_ERROR.getMessage());
    }

    @Override
    protected ResponseEntity<Object> handleExceptionInternal(Exception ex, Object body, HttpHeaders headers,
                                                             HttpStatusCode statusCode, WebRequest request) {
        if (!(request instanceof ServletWebRequest servletRequest)) {
            return super.handleExceptionInternal(ex, body, headers, statusCode, request);
        }
        HttpServletRequest httpRequest = servletRequest.getRequest();
        if (statusCode.is5xxServerError()) {
            failureLogger.logUnexpected(httpRequest, ex);
        }
        ErrorCode code = ErrorCode.fromStatus(statusCode);
        HttpHeaders responseHeaders = new HttpHeaders();
        if (headers != null) {
            responseHeaders.putAll(headers);
        }
        addCommonHeaders(httpRequest, statusCode, responseHeaders);
        return ResponseEntity.status(statusCode)
                .headers(responseHeaders)
                .body(factory.create(httpRequest, code));
    }

    private ResponseEntity<ErrorResponse> respond(HttpServletRequest request, CustomErrorCode code, String message) {
        HttpStatus status = code.getHttpStatus();
        HttpHeaders headers = new HttpHeaders();
        addCommonHeaders(request, status, headers);
        return ResponseEntity.status(status).headers(headers).body(factory.create(request, code, message));
    }

    private static void addCommonHeaders(HttpServletRequest request, HttpStatusCode status, HttpHeaders headers) {
        if (request.getAttribute(FailureLogger.REQUEST_ID) instanceof String requestId) {
            headers.set("X-Request-ID", requestId);
        }
        if (status.value() == HttpStatus.UNAUTHORIZED.value()) {
            headers.set(HttpHeaders.WWW_AUTHENTICATE, "Bearer");
        }
    }
}
