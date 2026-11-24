package com.connect11.server.domain.auth.service;

import com.connect11.server.domain.auth.dto.request.PasswordResetRequest;
import com.connect11.server.domain.auth.dto.response.PasswordResetResponse;

public interface PasswordResetService {

    /** @param resetToken Authorization 헤더에서 꺼낸 재설정 토큰 (없으면 null) */
    PasswordResetResponse reset(String resetToken, PasswordResetRequest request);
}
