package com.chukapoka.server.common.authority.oauth2.handler;

import com.chukapoka.server.common.authority.jwt.JwtTokenProvider;
import com.chukapoka.server.common.dto.BaseResponse;
import com.chukapoka.server.common.dto.CustomUserDetails;
import com.chukapoka.server.common.dto.TokenDto;
import com.chukapoka.server.common.dto.TokenResponseDto;
import com.chukapoka.server.common.entity.Token;
import com.chukapoka.server.common.enums.ResultType;
import com.chukapoka.server.common.repository.TokenRepository;
import com.chukapoka.server.user.dto.UserResponseDto;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;


/** OAuth2 인증이 성공했을 경우 */
@Slf4j
@Component
@RequiredArgsConstructor
public class CustomAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {
    private final JwtTokenProvider jwtTokenProvider;
    private final TokenRepository tokenRepository;
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {

        CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();
        // 1. authentication 유저 정보에 따른 토큰 생성
        TokenResponseDto token = saveToken(authentication, userDetails.getUser().getId().toString());
        // 2. baseResponse 객체 생성
        UserResponseDto userResponseDto = new UserResponseDto(ResultType.SUCCESS, userDetails.getEmail(), userDetails.getUserId(), token);
        BaseResponse<UserResponseDto> baseResponse = new BaseResponse<>(ResultType.SUCCESS, userResponseDto);
        // 3. JSON 형식으로 변환
        ObjectMapper objectMapper = new ObjectMapper();
        String jsonResponse = objectMapper.writeValueAsString(baseResponse);
        // 4. 응답 헤더 설정
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        // 5. 클라이언트에게 응답 전송
        response.getWriter().write(jsonResponse);
    }

    /** 토큰 생성 */
    private TokenResponseDto saveToken(Authentication authentication, String id){
        System.out.println("OAuth2 토큰 생성중");
        // JWT 토큰 생성
        TokenDto jwtToken = jwtTokenProvider.createToken(authentication);
        Token token = Token.builder()
                .key(id)
                .atValue(jwtToken.getAccessToken())
                .rtValue(jwtToken.getRefreshToken())
                .atExpiration(jwtToken.getAtExpiration())
                .rtExpiration(jwtToken.getRtExpiration())
                .build();
        return tokenRepository.save(token).toResponseDto();
    }
}