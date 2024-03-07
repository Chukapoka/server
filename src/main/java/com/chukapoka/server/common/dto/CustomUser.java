package com.chukapoka.server.common.dto;

import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Collection;
import java.util.Map;

/**
 * CustomUser 클래스는 Spring Security에서 제공하는 User 클래스를 확장하여 추가적인 사용자 정보를 저장하기 위한 클래스
 * 주로 사용자의 고유한 식별자(ID)를 추가로 저장하고자 할 때 사용
 */
@Getter
public class CustomUser extends User implements OAuth2User, UserDetails {

    private final Long userId;
    private Map<String, Object> attributes;
    private String attributeKey;


    public CustomUser(Long userId, String password, Collection<? extends GrantedAuthority> authorities) {
        super(String.valueOf(userId), password, authorities);
        this.userId = userId;
    }


    @Override
    public String getName() {
        return attributes.get(attributeKey).toString();
    }
    @Override
    public <A> A getAttribute(String name) {
        return OAuth2User.super.getAttribute(name);
    }

    @Override
    public Map<String, Object> getAttributes() {
        return null;
    }


}
