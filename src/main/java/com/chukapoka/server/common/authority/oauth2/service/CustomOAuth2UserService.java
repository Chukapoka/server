package com.chukapoka.server.common.authority.oauth2.service;

import com.chukapoka.server.common.authority.oauth2.dto.OAuth2Attribute;
import com.chukapoka.server.common.dto.CustomUserDetails;
import com.chukapoka.server.common.enums.Authority;
import com.chukapoka.server.user.entity.User;
import com.chukapoka.server.user.repository.UserRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.Optional;

@Slf4j
@Service
@Transactional
@RequiredArgsConstructor
public class CustomOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        log.debug("Loading user from OAuth2: {}", userRequest);

        // 1. 기본 OAuth2UserService 객체 생성
        OAuth2UserService<OAuth2UserRequest, OAuth2User> oAuth2UserService = new DefaultOAuth2UserService();
        System.out.println("oAuth2UserService = " + oAuth2UserService);
        // 2. OAuth2UserService를 사용하여 OAuth2User 정보를 가져온다.
        OAuth2User oAuth2User = oAuth2UserService.loadUser(userRequest);
        System.out.println("oAuth2User = " + oAuth2User);
        // 3. 클라이언트 등록 ID(google, naver, kakao)와 사용자 이름 속성을 가져온다.
        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        String userNameAttributeName = userRequest.getClientRegistration()
                .getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName();

        // 4. OAuth2UserService를 사용하여 가져온 OAuth2User 정보로 OAuth2Attribute 객체를 만든다.
        OAuth2Attribute oAuth2Attribute =
                OAuth2Attribute.of(registrationId, userNameAttributeName, oAuth2User.getAttributes());

        // 5. OAuth2Attribute의 속성값들을 Map으로 반환 받는다.
        Map<String, Object> memberAttribute = oAuth2Attribute.convertToMap();
        System.out.println("memberAttribute = " + memberAttribute);
        // 6. 사용자 email(또는 id) 정보를 가져온다.
        String email = (String) memberAttribute.get("email");
        log.debug("Email retrieved from OAuth2 attributes: {}", email);

        // 7. 이메일로 가입된 회원인지 조회한다.
        Optional<User> findMember = userRepository.findByEmail(email);


        User user;
        /** 회원이 존재하지 않을 경우 */
        if (findMember.isEmpty()) {
            // user의 패스워드가 null이기 때문에 OAuth 유저는 일반적인 로그인을 할 수 없음.
            user = User.builder()
                    .email(email)
                    .emailType((String) memberAttribute.get("emailType"))
                    .authorities("ROLE_"+Authority.USER.getAuthority())
                    .password(bCryptPasswordEncoder.encode((String) memberAttribute.get("id")))
                    .build();
            userRepository.save(user);
        }

        /** 회원이 존재할 경우 */
        else {
            user = findMember.get();
            user.setEmail(email); // Email이 변경 될 경우 업데이트
        }
        return new CustomUserDetails(user, memberAttribute);
    }
}