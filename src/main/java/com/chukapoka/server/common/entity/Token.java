package com.chukapoka.server.common.entity;

import com.chukapoka.server.common.dto.TokenResponseDto;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Builder;
import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
@Data
@Entity
@Table(name = "tb_token")
public class Token {

    @Id
    @Column(name = "token_key")
    private String key;

    @Column(name = "at_value")
    private String atValue; // access token

    @Column(name = "rt_value")
    private String rtValue; // refresh token
    // TODO: 현진 access token, refresh token 만료시간 컬럼 추가
    @Builder
    public Token(String key, String atValue, String rtValue) {
        this.key = key;
        this.atValue = atValue;
        this.rtValue = rtValue;
    }

    public Token updateValues(String accessToken, String refreshToken) {
        this.atValue = accessToken;
        this.rtValue = refreshToken;
        return this;
    }

    public TokenResponseDto toResponseDto(){
        return new TokenResponseDto(this.atValue);
    }


}
