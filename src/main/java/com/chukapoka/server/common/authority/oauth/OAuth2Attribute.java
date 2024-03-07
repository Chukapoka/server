package com.chukapoka.server.common.authority.oauth;

import lombok.*;

import java.util.HashMap;
import java.util.Map;

@ToString
@Builder(access = AccessLevel.PRIVATE) // Builder 메서드를 외부에서 사용하지 않으므로, Private 제어자로 지정
@Getter
public class OAuth2Attribute {
    private Map<String, Object> attributes; // 사용자 속성 정보를 담는 Map
    private String attributeKey; // 사용자 속성의 키 값
    private String email; // 이메일 정보
    private String name; // 이름 정보
    private String picture; // 프로필 사진 정보
    private String provider; // 제공자 정보


    public static OAuth2Attribute of(String provider, String attributeKey,
                                     Map<String, Object> attributes) {
        if (provider.equals("google")) {
            return ofGoogle(provider, attributeKey, attributes);
        }
        throw new RuntimeException();
    }

    /** Google 로그인일 경우 사용하는 메서드 */
    private static OAuth2Attribute ofGoogle(String provider, String attributeKey, Map<String, Object> attributes) {
        return OAuth2Attribute.builder()
                .email((String) attributes.get("email"))
                .provider(provider)
                .attributes(attributes)
                .attributeKey(attributeKey)
                .build();
    }

    // OAuth2User 객체에 넣어주기 위해서 Map으로 값들을 반환해준다.
    public Map<String, Object> convertToMap() {
        Map<String, Object> map = new HashMap<>();
        map.put("id", attributeKey);
        map.put("key", attributeKey);
        map.put("email", email);
        map.put("provider", provider);

        return map;
    }
}
