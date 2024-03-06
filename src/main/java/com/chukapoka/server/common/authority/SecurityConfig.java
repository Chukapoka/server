package com.chukapoka.server.common.authority;


import com.chukapoka.server.common.enums.Authority;
import com.chukapoka.server.common.repository.TokenRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    /**
     * Spring Security 6.1.0부터는 메서드 체이닝의 사용을 지양하고 람다식을 통해 함수형으로 설정하게 지향함
     */
    @Autowired
    private JwtTokenProvider jwtTokenProvider;
    @Autowired
    private TokenRepository tokenRepository;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .httpBasic(AbstractHttpConfigurer::disable)
                .csrf(AbstractHttpConfigurer::disable)
                .addFilterBefore(new JwtAuthenticationFilter(jwtTokenProvider, tokenRepository), UsernamePasswordAuthenticationFilter.class)
                .authorizeHttpRequests((authorizeRequests) -> {
                            authorizeRequests
                                    .requestMatchers("/api/user/emailCheck", "/api/user", "/api/user/authNumber", "/api/health").anonymous()
                                    .requestMatchers("/api/user/logout", "api/user/reissue","/api/tree","api/tree/**","api/treeItem","api/treeItem/**").hasRole(Authority.USER.getAuthority());//  hasAnyRole은 "ROLE_" 접두사를 자동으로 추가해줌 하지만 Authority는 "ROLE_USER"로 설정해야했음 이것떄문에 회원가입할떄 권한이 안넘어갔음
                }
                );

        return http.build();
    }

    // 비밀번호 암호화를 위해  BCryptPasswordEncoder 등록
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
