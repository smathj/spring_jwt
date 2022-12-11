package com.springboot.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.domain.AuditorAware;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

import java.util.Optional;
import java.util.UUID;

@Configuration
@EnableJpaAuditing
public class JpaAuditingConfiguration {
    // * 이렇게 있어야할듯
    /*
    @Bean
    public AuditorAware<String> auditorProvider() {
        // 실전에서는 시큐리티나 세션에서 해당 아이디 꺼내서,
        // 그 유저 아이디를 넣어주면된다 그렇게하면 자동으로 채워넣는다
        return () -> Optional.of(UUID.randomUUID().toString());
    }
    */
}
