package com.chukapoka.server.common.authority;


import com.chukapoka.server.common.authority.jwt.JwtAuthenticationFilter;
import com.chukapoka.server.common.authority.jwt.JwtTokenProvider;
import com.chukapoka.server.common.enums.Authority;
import com.chukapoka.server.common.repository.TokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    /**
     * Spring Security 6.1.0부터는 메서드 체이닝의 사용을 지양하고 람다식을 통해 함수형으로 설정하게 지향함
     */
    private final JwtTokenProvider jwtTokenProvider;
    private final TokenRepository tokenRepository;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        /** rest api 설정 */
        http
                .headers(headers -> headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin)) // h2 <frame>요소를 사용 비활성화
                .httpBasic(AbstractHttpConfigurer::disable) // 기본 인증 로그인 비활성화
                .logout(AbstractHttpConfigurer::disable) // 기본 로그아웃 비활성화
                .formLogin(AbstractHttpConfigurer::disable) // 기본 로그인 비활성화
                .csrf(AbstractHttpConfigurer::disable) // csrf 비활성화 -> cookie를 사용하지 않으면 꺼도 된다. (cookie를 사용할 경우 httpOnly(XSS 방어), sameSite(CSRF 방어)로 방어해야 한다.)
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) // 세션관리 정책을 STATELESS(세션이 있으면 쓰지도 않고, 없으면 만들지도 않는다)
                .addFilterAfter(new JwtAuthenticationFilter(jwtTokenProvider, tokenRepository), UsernamePasswordAuthenticationFilter.class);

        /** request 인증, 인가 설정 */
        http
                .authorizeHttpRequests((authorizeRequests) -> {
                    authorizeRequests
                            .requestMatchers("/swagger-ui/**", "/v3/api-docs/**","/h2-console/**").permitAll()
                            .requestMatchers("/api/user/emailCheck", "/api/user", "/api/user/authNumber").anonymous()
                            .requestMatchers("/api/user/logout", "api/user/reissue", "api/tree/**","api/treeItem/**").hasRole(Authority.USER.getAuthority()//  hasAnyRole은 "ROLE_" 접두사를 자동으로 추가해줌 하지만 Authority는 "ROLE_USER"로 설정해야했음 이것떄문에 회원가입할떄 권한이 안넘어갔음

                            );
                });
        return http.build();
    }

    // 비밀번호 암호화를 위해  BCryptPasswordEncoder 등록
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
