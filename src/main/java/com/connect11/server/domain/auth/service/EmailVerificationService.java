package com.connect11.server.domain.auth.service;

import com.connect11.server.domain.auth.dto.request.EmailSendRequest;
import com.connect11.server.domain.auth.dto.request.EmailVerifyRequest;
import com.connect11.server.domain.auth.dto.response.EmailSendResponse;
import com.connect11.server.domain.auth.dto.response.EmailVerifyResponse;

public interface EmailVerificationService {

    EmailSendResponse send(EmailSendRequest request);

    EmailVerifyResponse verify(EmailVerifyRequest request);
}
