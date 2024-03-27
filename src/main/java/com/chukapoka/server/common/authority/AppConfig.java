package com.chukapoka.server.common.authority;


import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.modelmapper.convention.MatchingStrategies;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@RequiredArgsConstructor
public class AppConfig {
    @Bean
    public ModelMapper modelMapper() {
        ModelMapper modelMapper = new ModelMapper();
        /** 연결 전략 : 같은 타입의 필드명이 같은 경우만 동작 */
        modelMapper.getConfiguration().setMatchingStrategy(MatchingStrategies.LOOSE).setSkipNullEnabled(true).setFieldMatchingEnabled(true)
                .setAmbiguityIgnored(true) // id속성을 매핑에서 제외
                .setFieldAccessLevel(org.modelmapper.config.Configuration.AccessLevel.PRIVATE);
        return modelMapper;
    }
}
