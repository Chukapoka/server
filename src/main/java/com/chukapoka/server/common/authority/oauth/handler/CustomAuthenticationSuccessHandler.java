package com.chukapoka.server.common.authority.oauth.handler;

import com.chukapoka.server.common.authority.jwt.JwtTokenProvider;
import com.chukapoka.server.common.dto.TokenDto;
import com.chukapoka.server.common.entity.Token;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;

import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Slf4j
@Component
@RequiredArgsConstructor
public class CustomAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {
    private final JwtTokenProvider jwtTokenProvider;
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        TokenDto jwtToken = jwtTokenProvider.createToken(authentication);
        Token token = Token.builder()
                .key(authentication.getName())
                .atValue(jwtToken.getAccessToken())
                .rtValue(jwtToken.getRefreshToken())
                .atExpiration(jwtToken.getAtExpiration())
                .rtExpiration(jwtToken.getRtExpiration())
                .build();

        super.onAuthenticationSuccess(request, response, authentication);
    }
}
