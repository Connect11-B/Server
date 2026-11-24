package com.connect11.server.domain.auth.service;

import com.connect11.server.domain.auth.dto.request.PasswordResetRequest;
import com.connect11.server.domain.auth.dto.response.PasswordResetResponse;

public interface PasswordResetService {

    PasswordResetResponse reset(String resetToken, PasswordResetRequest request);
}
