package com.connect11.server.domain.auth.entity;

public record EmailVerification(
        String id,
        String email,
        VerificationPurpose purpose,
        String codeHash,
        long expiresAtEpochSecond,
        boolean used) {
}