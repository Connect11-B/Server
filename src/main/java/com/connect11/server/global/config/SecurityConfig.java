package com.connect11.server.global.config;

import com.connect11.server.global.security.JwtAuthenticationFilter;
import com.connect11.server.global.security.JwtProvider;
import com.connect11.server.global.security.RestAccessDeniedHandler;
import com.connect11.server.global.security.RestAuthenticationEntryPoint;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtProvider jwtProvider;
    private final RestAuthenticationEntryPoint authenticationEntryPoint;
    private final RestAccessDeniedHandler accessDeniedHandler;
    private final AppProperties appProperties;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)      // CSRF 필요없음
                .formLogin(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .logout(AbstractHttpConfigurer::disable)
                .cors(Customizer.withDefaults())
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .exceptionHandling(e -> e
                        .authenticationEntryPoint(authenticationEntryPoint)
                        .accessDeniedHandler(accessDeniedHandler))
                .addFilterBefore(new JwtAuthenticationFilter(jwtProvider), UsernamePasswordAuthenticationFilter.class)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                        .requestMatchers("/actuator/health", "/error").permitAll()

                        // 비회원
                        .requestMatchers(HttpMethod.POST,
                                "/api/v1/auth/email/send",
                                "/api/v1/auth/email/verify",
                                "/api/v1/auth/signup",
                                "/api/v1/auth/login",
                                "/api/v1/auth/refresh",
                                "/api/v1/password/reset").permitAll()
                        .requestMatchers(HttpMethod.GET,
                                "/api/v1/items",
                                "/api/v1/items/*",
                                "/api/v1/operating/hours",
                                "/api/v1/operating/exceptions",
                                "/api/v1/files/images/*").permitAll()

                        // 관리자
                        .requestMatchers("/api/v1/admin/**").hasRole("ADMIN")

                        // 학생
                        .requestMatchers(HttpMethod.POST, "/api/v1/rentals", "/api/v1/rentals/*/cancel",
                                "/api/v1/inquiries", "/api/v1/files/signatures").hasRole("STUDENT")
                        .requestMatchers(HttpMethod.GET, "/api/v1/rentals/me", "/api/v1/rentals/me/*",
                                "/api/v1/inquiries/me").hasRole("STUDENT")

                        .anyRequest().authenticated());
        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        List<String> origins = appProperties.cors() == null || appProperties.cors().allowedOrigins() == null
                ? List.of()
                : appProperties.cors().allowedOrigins().stream()
                .map(String::trim)
                .filter(o -> !o.isEmpty() && !o.equals("*"))
                .toList();

        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(origins);
        config.setAllowedMethods(List.of("GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(List.of("Authorization", "Content-Type"));
        config.setAllowCredentials(true);   // refresh token 쿠키. 허용 Origin은 위에서 명시한 목록뿐이다.
        config.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }
}