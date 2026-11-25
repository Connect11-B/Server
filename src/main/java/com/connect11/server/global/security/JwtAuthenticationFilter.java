package com.connect11.server.global.security;

import com.connect11.server.domain.auth.repository.RefreshSessionStore;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final String BEARER_PREFIX = "Bearer ";
    private static final String RESET_PATH = "/api/v1/password/reset";
    private static final String LOGOUT_PATH = "/api/v1/auth/logout";

    private final JwtProvider jwtProvider;
    private final RefreshSessionStore sessionStore;

    public JwtAuthenticationFilter(JwtProvider jwtProvider, RefreshSessionStore sessionStore) {
        this.jwtProvider = jwtProvider;
        this.sessionStore = sessionStore;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return RESET_PATH.equals(request.getRequestURI());
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (header != null && header.regionMatches(true, 0, BEARER_PREFIX, 0, BEARER_PREFIX.length())) {
            String token = header.substring(BEARER_PREFIX.length()).trim();
            jwtProvider.parse(token)
                    .filter(authUser -> isLogout(request) || sessionActive(authUser))
                    .ifPresent(authUser -> {
                        var authentication = new UsernamePasswordAuthenticationToken(
                                authUser, null,
                                List.of(new SimpleGrantedAuthority("ROLE_" + authUser.role().name())));
                        SecurityContextHolder.getContext().setAuthentication(authentication);
                    });
        }
        chain.doFilter(request, response);
    }

    private boolean isLogout(HttpServletRequest request) {
        return "POST".equals(request.getMethod()) && LOGOUT_PATH.equals(request.getRequestURI());
    }

    private boolean sessionActive(AuthUser authUser) {
        try {
            return sessionStore.isActive(authUser.sessionId(), authUser.userId());
        } catch (RuntimeException e) {
            log.warn("세션 상태 확인 실패: cause={}", e.getClass().getSimpleName());
            return false;
        }
    }
}
