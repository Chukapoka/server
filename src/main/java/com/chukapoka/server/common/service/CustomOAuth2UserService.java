package com.chukapoka.server.common.service;

import com.chukapoka.server.common.authority.oauth.OAuth2Attribute;
import com.chukapoka.server.common.dto.CustomUser;
import com.chukapoka.server.common.enums.Authority;
import com.chukapoka.server.user.entity.User;
import com.chukapoka.server.user.repository.UserRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Collections;
import java.util.Map;
import java.util.Optional;


@Slf4j
@Service
@Transactional
@RequiredArgsConstructor
/** OAuth 2.0 인증을 통해 사용자 정보를 가져오는 역할을 담당*/
public class CustomOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        // 1. 유저 정보(attributes) 가져온다
        OAuth2UserService<OAuth2UserRequest, OAuth2User> service = new DefaultOAuth2UserService();
        OAuth2User oAuth2User = service.loadUser(userRequest);
        System.out.println("oAuth2User.getAttributes() = " + oAuth2User.getAttributes());

        // 2. 클라이언트 등록 ID(google, kakao)와 사용자 이름 속성을 가져온다.
        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        // 3. OAuth2UserService를 사용하여 가져온 OAuth2User 정보로 OAuth2Attribute 객체를 만든다.
        OAuth2Attribute oAuth2Attribute = OAuth2Attribute.of(registrationId, oAuth2User.getAttributes());
        // 4. OAuth2Attribute의 속성값들을 Map으로 반환 받는다.
        Map<String, Object> memberAttribute = oAuth2Attribute.convertToMap();
        System.out.println("memberAttribute = " + memberAttribute);
        // 5. 사용자 email(또는 id) 정보를 가져온다.
        Optional<User> findUser = userRepository.findByEmail((String) memberAttribute.get("email"));
        /** 회원이 존재하지 않을경우 */
        if(findUser.isEmpty()){
            System.out.println("소셜로그인 회원가입 진행중" );
            createUser(memberAttribute);
            return new DefaultOAuth2User(
                    Collections.singleton(new SimpleGrantedAuthority("ROLE_"+Authority.USER.getAuthority())),
                    memberAttribute, "email");
        }
        /** 회원이 존재할 경우 */
        // 회원의 권한과, 회원속성, 속성이름을 이용해 DefaultOAuth2User 객체를 생성해 반환한다.
        System.out.println("소션로그인 진행");
        return new DefaultOAuth2User(
                Collections.singleton(new SimpleGrantedAuthority("ROLE_"+Authority.USER.getAuthority())),
                memberAttribute, "email");
    }

    private User createUser(Map<String, Object> memberAttribute) {
        User newUser = User.builder()
                .email((String) memberAttribute.get("email"))
                .emailType((String) memberAttribute.get("provider"))
                .updatedAt(LocalDateTime.now())
                .password(bCryptPasswordEncoder.encode((String) memberAttribute.get("id")))
                .role("ROLE_"+Authority.USER.getAuthority())
                .build();
       return userRepository.save(newUser);
    }
}
