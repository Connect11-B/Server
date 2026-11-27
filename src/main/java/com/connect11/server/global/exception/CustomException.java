package com.connect11.server.global.exception;

import com.connect11.server.global.common.CustomErrorCode;

public class CustomException extends BusinessException {

    public CustomException(CustomErrorCode errorCode) {
        super(errorCode);
    }

    public CustomException(CustomErrorCode errorCode, String message) {
        super(errorCode, message);
    }
}
