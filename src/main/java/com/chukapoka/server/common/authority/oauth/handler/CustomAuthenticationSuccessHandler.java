package com.chukapoka.server.common.authority.oauth.handler;

import com.chukapoka.server.common.authority.jwt.JwtTokenProvider;
import com.chukapoka.server.common.dto.TokenDto;
import com.chukapoka.server.common.dto.TokenResponseDto;
import com.chukapoka.server.common.entity.Token;
import com.chukapoka.server.common.enums.Authority;
import com.chukapoka.server.common.repository.TokenRepository;
import com.chukapoka.server.user.entity.User;
import com.chukapoka.server.user.repository.UserRepository;
import com.chukapoka.server.user.sevice.UserService;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

/** OAuth2 인증이 성공했을 경우 */
@Slf4j
@Component
@RequiredArgsConstructor
public class CustomAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {
    private final JwtTokenProvider jwtTokenProvider;
    private final TokenRepository tokenRepository;
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();


    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        log.debug("Successauthentication = {}", authentication);
        // OAuth2User로 캐스팅하여 인증된 사용자 정보를 가져온다.
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        System.out.println("oAuth2User = " + oAuth2User);

        String id = oAuth2User.getAttribute("id");
        String email = oAuth2User.getAttribute("email");
        String provider = oAuth2User.getAttribute("provider");

        User user = userRepository.findByEmail(email).orElse(null);

        TokenResponseDto accessToken =  saveToken(authentication, id);
        System.out.println("accessToken = " + accessToken);

        // 토큰을 요청 본문으로 전달
        Map<String, Object> responseBody = new HashMap<>();
        responseBody.put("email", email);
        responseBody.put("userId", id);
        responseBody.put("accessToken", accessToken.getAccessToken());

        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        new ObjectMapper().writeValue(response.getWriter(), responseBody);
    }

    private TokenResponseDto saveToken(Authentication authentication, String id){
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
    private void createUser(Map<String, Object> memberAttribute) {
        User newUser = User.builder()
                .email((String) memberAttribute.get("email"))
                .emailType((String) memberAttribute.get("provider"))
                .updatedAt(LocalDateTime.now())
                .password(bCryptPasswordEncoder.encode((String) memberAttribute.get("id")))
                .role("ROLE_"+Authority.USER.getAuthority())
                .build();
        userRepository.save(newUser);
    }
}
