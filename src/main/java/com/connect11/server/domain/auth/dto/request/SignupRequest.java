package com.connect11.server.domain.auth.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

// role/status는 요청에서 받지 않는다. (서버가 STUDENT로 고정)
public record SignupRequest(
        @NotBlank @Size(max = 100) String signupToken,
        @NotBlank @Email @Size(max = 255) String email,
        @NotBlank @Size(max = 256) String password,
        @NotBlank @Size(max = 100) String displayName,
        // users.student_number는 NOT NULL·UNIQUE(최대 20자). 영문자·숫자만 허용한다.
        @NotBlank @Pattern(regexp = "[0-9A-Za-z]{1,20}") String studentNumber) {

    // 로그에 비밀번호·토큰이 찍히지 않게 한다.
    @Override
    public String toString() {
        return "SignupRequest[***]";
    }
}
