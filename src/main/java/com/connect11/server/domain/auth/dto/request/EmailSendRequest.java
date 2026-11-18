package com.connect11.server.domain.auth.dto.request;

import com.connect11.server.domain.auth.entity.VerificationPurpose;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

public record EmailSendRequest(
        @NotBlank @Email @Size(max = 255) String email,
        @NotNull VerificationPurpose purpose) {
}