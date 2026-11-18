package com.connect11.server.global.security;

import com.connect11.server.domain.user.entity.Role;

public record AuthUser(Long userId, Role role, String sessionId) {

}