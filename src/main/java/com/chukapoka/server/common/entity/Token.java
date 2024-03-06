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

import java.time.LocalDateTime;

@Getter
@NoArgsConstructor
@Data
@Entity
@Table(name = "tb_token")
@Builder
public class Token {

    @Id
    @Column(name = "token_key")
    private String key;

    @Column(name = "at_value")
    private String atValue; // access token

    @Column(name = "rt_value")
    private String rtValue; // refresh token

    // 만료 시간을 나타내는 컬럼 추가
    @Column(name = "at_expiration")
    private LocalDateTime atExpiration; // access token 만료 시간

    @Column(name = "rt_expiration")
    private LocalDateTime rtExpiration; // refresh token 만료 시간

    public Token(String key, String atValue, String rtValue, LocalDateTime atExpiration, LocalDateTime rtExpiration) {
        this.key = key;
        this.atValue = atValue;
        this.rtValue = rtValue;
        this.atExpiration = atExpiration;
        this.rtExpiration = rtExpiration;
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
