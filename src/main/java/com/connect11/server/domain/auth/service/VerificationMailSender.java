package com.connect11.server.domain.auth.service;

import com.connect11.server.domain.auth.entity.VerificationPurpose;

public interface VerificationMailSender {

    void sendCode(String to, String code, VerificationPurpose purpose);
}