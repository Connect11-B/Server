package com.connect11.server.global.exception;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class FailureLogger {

    public static final String REQUEST_ID = FailureLogger.class.getName() + ".REQUEST_ID";

    public void logUnexpected(HttpServletRequest request, Exception exception) {
        log.error("처리되지 않은 예외: requestId={} {} {}",
                request.getAttribute(REQUEST_ID), request.getMethod(), request.getRequestURI(), exception);
    }
}
