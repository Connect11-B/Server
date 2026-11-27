package com.connect11.server.domain.auth.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record PasswordResetRequest(@NotBlank @Size(max = 256) String newPassword) {

    @Override
    public String toString() {
        return "PasswordResetRequest[***]";
    }
}
