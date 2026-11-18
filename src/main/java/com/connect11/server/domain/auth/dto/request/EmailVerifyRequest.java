package com.connect11.server.domain.auth.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record EmailVerifyRequest(
        @NotBlank @Size(max = 64) String verificationId,
        @NotBlank @Pattern(regexp = "\\d{6}") String code) {
}