package com.connect11.server.domain.auth.dto.response;

public record EmailSendResponse(String verificationId,
                                long expiresIn,
                                long resendAfter) {
}