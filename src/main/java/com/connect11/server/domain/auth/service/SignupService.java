package com.connect11.server.domain.auth.service;

import com.connect11.server.domain.auth.dto.request.SignupRequest;
import com.connect11.server.domain.auth.dto.response.SignupResponse;

public interface SignupService {

    SignupResponse signup(SignupRequest request);
}
