package com.connect11.server.domain.auth.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record LoginRequest(
        @NotBlank @Size(max = 255) String username,
        @NotBlank @Size(max = 256) String password) {

    @Override
    public String toString() {
        return "LoginRequest[***]";
    }
}
