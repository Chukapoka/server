package com.chukapoka.server.common.authority.oauth.handler;

import com.chukapoka.server.common.authority.jwt.JwtTokenProvider;
import com.chukapoka.server.common.dto.TokenDto;
import com.chukapoka.server.common.entity.Token;
import com.chukapoka.server.common.enums.Authority;
import com.chukapoka.server.common.repository.TokenRepository;
import com.chukapoka.server.user.entity.User;
import com.chukapoka.server.user.repository.UserRepository;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.LocalDateTime;
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
        // OAuth2User로 캐스팅하여 인증된 사용자 정보를 가져온다.
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        System.out.println("oAuth2User.getAttributes() = " + oAuth2User.getAttributes());
        // 사용자 이메일을 가져온다.
        String email = oAuth2User.getAttribute("email");
        // 서비스 제공 플랫폼(GOOGLE, KAKAO, NAVER)이 어디인지 가져온다.
        String provider = oAuth2User.getAttribute("provider");
        // CustomOAuth2UserService에서 셋팅한 로그인한 회원 존재 여부를 가져온다.
        boolean isExist = oAuth2User.getAttribute("exist");
        User user = userRepository.findByEmail(email).orElse(null);

//        if (user != null) {
//            // User exists
//            log.info("User exists: {}", email);
//            System.out.println("oAuth2User = " + oAuth2User.getAttributes().get("id"));
//            TokenDto jwtToken = jwtTokenProvider.createToken(authentication);
//            Token token = Token.builder()
//                    .key(email)
//                    .atValue(jwtToken.getAccessToken())
//                    .rtValue(jwtToken.getRefreshToken())
//                    .atExpiration(jwtToken.getAtExpiration())
//                    .rtExpiration(jwtToken.getRtExpiration())
//                    .build();
//            tokenRepository.save(token);
//            // Redirect to the home page or any other desired page
//            response.sendRedirect("/login");
//        } else {
//            // User does not exist
//            log.info("User does not exist: {}", email);
//            System.out.println("oAuth2User = " + oAuth2User);
//            System.out.println("oAuth2User = " + oAuth2User.getAttributes().get("id"));
//            // Redirect to the registration page or any other desired page
//            response.sendRedirect("/api/tree");

//        }


        super.onAuthenticationSuccess(request, response, authentication);
    }

    /** 새로운 생성자 저장 */
    private User createUser(Map<String, Object> memberAttribute) {
        User newUser = User.builder()
                .id((Long) memberAttribute.get("id"))
                .email((String) memberAttribute.get("email"))
                .emailType((String) memberAttribute.get("provider"))
                .updatedAt(LocalDateTime.now())
                .password(bCryptPasswordEncoder.encode("chukapoka"))
                .role(Authority.USER.getAuthority())
                .build();
        return userRepository.save(newUser);
    }
}
