package com.connect11.server.domain.auth.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record SignupRequest(
        @NotBlank @Size(max = 100) String signupToken,
        @NotBlank @Email @Size(max = 255) String email,
        @NotBlank @Size(max = 256) String password,
        @NotBlank @Size(max = 100) String displayName,
        @NotBlank @Pattern(regexp = "[0-9]{4}") String studentNumber) {

    @Override
    public String toString() {
        return "SignupRequest[***]";
    }
}
