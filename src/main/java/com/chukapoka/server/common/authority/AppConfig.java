package com.chukapoka.server.common.authority;


import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.modelmapper.convention.MatchingStrategies;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@RequiredArgsConstructor
public class AppConfig {

    /** ModelMapper 사용하기위한 Bean 등록 */
    @Bean
    public ModelMapper modelMapper() {
        ModelMapper modelMapper = new ModelMapper();
        /** 연결 전략 : 같은 타입의 필드명이 같은 경우만 동작 */
        modelMapper.getConfiguration().setMatchingStrategy(MatchingStrategies.LOOSE).setSkipNullEnabled(true).setFieldMatchingEnabled(true)
                .setAmbiguityIgnored(true) // id속성을 매핑에서 제외
                .setFieldAccessLevel(org.modelmapper.config.Configuration.AccessLevel.PRIVATE);
        return modelMapper;
    }

    /** 비밀번호 암호화를 위해  BCryptPasswordEncoder 등록 */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
