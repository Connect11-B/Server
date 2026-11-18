package com.connect11.server.global.config;

import java.time.Clock;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class TimeConfig {

    // 만료 판단에 쓰는 시계. 테스트에서 고정 시계로 바꿔 끼울 수 있게 Bean으로 둔다.
    @Bean
    public Clock clock() {
        return Clock.systemUTC();
    }
}