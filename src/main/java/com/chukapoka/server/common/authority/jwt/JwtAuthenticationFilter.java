package com.chukapoka.server.common.authority.jwt;

import com.chukapoka.server.common.entity.Token;
import com.chukapoka.server.common.repository.TokenRepository;
import io.jsonwebtoken.lang.Strings;
import jakarta.persistence.EntityNotFoundException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.annotation.WebFilter;
import jakarta.servlet.http.HttpServletRequest;
import lombok.AllArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.GenericFilterBean;


import java.io.IOException;

@WebFilter
@AllArgsConstructor
public class JwtAuthenticationFilter extends GenericFilterBean {

    public static final String AUTHORIZATION_HEADER = "Authorization";
    public static final String BEARER_PREFIX = "Bearer";
    private final JwtTokenProvider jwtTokenProvider;
    private final TokenRepository tokenRepository;

    // 실제 필터링 로직은 doFilterInternal 에 들어감
    // JWT 토큰의 인증 정보를 현재 쓰레드의 SecurityContext 에 저장하는 역할 수행
    /** 클라이언트로부터의 토큰은 무조건 access token */
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        // 1. Request Header 에서 토큰을 꺼냄
        String accessToken = resolveToken((HttpServletRequest) request);
        // 2. validateToken 으로 토큰 유효성 검사
        // 정상 토큰이면 해당 토큰으로 Authentication 을 가져와서 SecurityContext 에 저장
        if (StringUtils.hasText(accessToken)) {
            /** access token이 유효한 경우 */
            if (jwtTokenProvider.validateToken(accessToken) && !jwtTokenProvider.isTokenExpired(accessToken)) {
                Authentication authentication = jwtTokenProvider.getAuthentication(accessToken);
                SecurityContextHolder.getContext().setAuthentication(authentication);


            }
            /** access token이 유효하지 않고, /api/user/reissue 요청일 경우 */
            else if (isReissueRequest(((HttpServletRequest) request).getRequestURL().toString())){
                /** access token이 유효하지 않거나 만료된 경우 */
                Token token = tokenRepository.findByAtValue(accessToken).orElseThrow(() -> new EntityNotFoundException("존재하지 않은 액세스 토큰입니다."));
                String refreshToken = token.getRtValue();
                if (jwtTokenProvider.validateToken(refreshToken) && !jwtTokenProvider.isTokenExpired(refreshToken)) {
                    /** access token이 만료된 경우 + refresh token은 유효한 경우 */
                    Authentication authentication = jwtTokenProvider.getAuthentication(refreshToken);
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            }
        }
        chain.doFilter(request, response);
    }

    // Request Header 에서 토큰 정보를 꺼내오기
    private String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader( AUTHORIZATION_HEADER);
        return (StringUtils.hasText(bearerToken) && bearerToken.startsWith(BEARER_PREFIX)) ?
                Strings.hasLength(bearerToken) ? bearerToken.substring(7) : null : null;
    }

    private boolean isReissueRequest (String requestUrl) {
        return requestUrl.contains("/api/user/reissue");
    }

}