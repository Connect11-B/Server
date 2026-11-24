package com.connect11.server.domain.auth.dto.response;

import com.connect11.server.domain.auth.entity.VerificationPurpose;
import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record EmailVerifyResponse(
        VerificationPurpose purpose,
        String signupToken,
        String resetToken,
        long expiresIn) {

    public static EmailVerifyResponse of(VerificationPurpose purpose, String token, long expiresIn) {
        return purpose == VerificationPurpose.SIGNUP
                ? new EmailVerifyResponse(purpose, token, null, expiresIn)
                : new EmailVerifyResponse(purpose, null, token, expiresIn);
    }
}
