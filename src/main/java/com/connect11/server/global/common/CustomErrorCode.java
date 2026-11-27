package com.connect11.server.global.common;

import org.springframework.http.HttpStatus;

public interface CustomErrorCode {
    HttpStatus getHttpStatus();
    String getErrorCode();
    String getMessage();
}
