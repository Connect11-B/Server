package com.connect11.server.domain.auth.entity;

public record VerificationToken(
        VerificationPurpose purpose,
        String email,
        long expiresAtEpochSecond,
        boolean used) {
}