package com.connect11.server.global.exception;

import com.connect11.server.global.common.CustomErrorCode;
import lombok.Getter;

@Getter
public class BusinessException extends RuntimeException {

    private final CustomErrorCode errorCode;

    public BusinessException(CustomErrorCode errorCode) {
        this(errorCode, errorCode.getMessage());
    }

    public BusinessException(CustomErrorCode errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
    }
}
