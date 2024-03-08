package com.chukapoka.server.common.authority.oauth;

import com.chukapoka.server.common.enums.Authority;
import com.chukapoka.server.common.enums.EmailType;
import lombok.*;

import java.util.HashMap;
import java.util.Map;

@ToString
@Builder(access = AccessLevel.PRIVATE) // Builder 메서드를 외부에서 사용하지 않으므로, Private 제어자로 지정
@Getter
public class OAuth2Attribute {
    private Map<String, Object> attributes; // 사용자 속성 정보를 담는 Map
    private String attributeId; // 사용자 속성의 키 값
    private String email; // 이메일 정보
    private String name; //사용자 정보
    private String provider; //GOOGLE , NAVER



    public static OAuth2Attribute of(String provider, Map<String, Object> attributes) {
        if (provider.equals("google")) {
            return ofGoogle( attributes);
        }
        throw new RuntimeException();
    }

    /** Google 로그인일 경우 사용하는 메서드 */
    private static OAuth2Attribute ofGoogle( Map<String, Object> attributes) {
        return OAuth2Attribute.builder()
                .attributes(attributes)
                .attributeId((String) attributes.get("sub"))
                .email((String) attributes.get("email"))
                .name((String) attributes.get("name"))
                .provider(EmailType.GOOGLE.name())
                .build();
    }

    /** OAuth2User 객체에 넣어주기 위해서 Map으로 값들을 반환 */
    public Map<String, Object> convertToMap() {
        Map<String, Object> map = new HashMap<>();
        map.put("id", attributeId);
        map.put("email", email);
        map.put("name", name);
        map.put("provider", provider);
        return map;
    }
}
