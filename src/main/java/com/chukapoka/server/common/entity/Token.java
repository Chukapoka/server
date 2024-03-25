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

import javax.crypto.KEM;

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

    // 만료 시간을 나타내는 컬럼 추가
    @Column(name = "at_expiration")
    private String atExpiration; // access token 만료 시간

    @Column(name = "rt_expiration")
    private String rtExpiration; // refresh token 만료 시간

    @Builder
    public Token(String key, String atValue, String rtValue, String atExpiration, String rtExpiration) {
        this.key = key;
        this.atValue = atValue;
        this.rtValue = rtValue;
        this.atExpiration = atExpiration;
        this.rtExpiration = rtExpiration;
    }
    
    public TokenResponseDto toResponseDto(){
        return new TokenResponseDto(this.atValue);
    }

}
