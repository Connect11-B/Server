package com.connect11.server.global.common;

import org.springframework.http.HttpStatus;

public interface CustomResponseKind {
    HttpStatus getHttpStatus();
    String getName();
    String getFeatureCode();
}
