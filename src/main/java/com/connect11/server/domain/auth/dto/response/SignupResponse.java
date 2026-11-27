package com.connect11.server.domain.auth.dto.response;

import com.connect11.server.domain.user.entity.Role;
import com.connect11.server.domain.user.entity.User;

public record SignupResponse(Long userId, String email, String displayName, Role role) {

    public static SignupResponse from(User user) {
        return new SignupResponse(user.getId(), user.getEmail(), user.getName(), user.getRole());
    }
}
