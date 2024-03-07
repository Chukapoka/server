package com.chukapoka.server.common.authority;


import com.chukapoka.server.common.authority.jwt.JwtAuthenticationFilter;
import com.chukapoka.server.common.authority.jwt.JwtTokenProvider;
import com.chukapoka.server.common.authority.oauth.handler.CustomAuthenticationFailureHandler;
import com.chukapoka.server.common.authority.oauth.handler.CustomAuthenticationSuccessHandler;
import com.chukapoka.server.common.enums.Authority;
import com.chukapoka.server.common.repository.TokenRepository;
import com.chukapoka.server.common.service.CustomOAuth2UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
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
    @Autowired
    private final JwtTokenProvider jwtTokenProvider;
    @Autowired
    private final TokenRepository tokenRepository;
    private final CustomOAuth2UserService customOAuth2UserService;
    private final CustomAuthenticationFailureHandler oAuth2LoginFailureHandler;
    private final CustomAuthenticationSuccessHandler oAuth2LoginSuccessHandler;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        /** rest api 설정 */
        http
                .httpBasic(AbstractHttpConfigurer::disable) // 기본 인증 로그인 비활성화
                .logout(AbstractHttpConfigurer::disable) // 기본 로그아웃 비활성화
                .csrf(AbstractHttpConfigurer::disable) // csrf 비활성화 -> cookie를 사용하지 않으면 꺼도 된다. (cookie를 사용할 경우 httpOnly(XSS 방어), sameSite(CSRF 방어)로 방어해야 한다.)
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) // 세션관리 정책을 STATELESS(세션이 있으면 쓰지도 않고, 없으면 만들지도 않는다)
                .addFilterBefore(new JwtAuthenticationFilter(jwtTokenProvider, tokenRepository), UsernamePasswordAuthenticationFilter.class);

        /** request 인증, 인가 설정 */
        http
                .authorizeHttpRequests((authorizeRequests) -> {
                            authorizeRequests
                                    .requestMatchers("/api/user/emailCheck", "/api/user", "/api/user/authNumber", "/api/health").anonymous()
                                    .requestMatchers("/api/user/logout", "api/user/reissue", "/api/tree", "api/tree/**", "api/treeItem", "api/treeItem/**").hasRole(Authority.USER.getAuthority())//  hasAnyRole은 "ROLE_" 접두사를 자동으로 추가해줌 하지만 Authority는 "ROLE_USER"로 설정해야했음 이것떄문에 회원가입할떄 권한이 안넘어갔음
                                    .anyRequest().authenticated(); // 테스트를 위한 모든권한 설정(테스트 후 삭제 예정)

                });

        /** OAuth2 로그인 설정 */
        http
                .oauth2Login((oauth2) ->
                        oauth2
                                .userInfoEndpoint(userInfoEndpointConfig ->
                                        userInfoEndpointConfig
                                                .userService(customOAuth2UserService)) // OAuth2 로그인시 사용자 정보를 가져오는 엔드포인트와 사용자 서비스를 설정
                                .failureHandler(oAuth2LoginFailureHandler) // OAuth2 로그인 실패시 처리할 핸들러를 지정
                                .successHandler(oAuth2LoginSuccessHandler) // OAuth2 로그인 성공시 처리할 핸들러를 지정
                );

        return http.build();
    }

    // 비밀번호 암호화를 위해  BCryptPasswordEncoder 등록
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
