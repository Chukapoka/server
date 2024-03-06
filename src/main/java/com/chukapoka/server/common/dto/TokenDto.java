package com.chukapoka.server.common.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
/**
 * 클라이언트에 토큰을 보내기 위한 DTO
 */
@Data
@AllArgsConstructor
@Builder
public class TokenDto {
    private String grantType; // JWT에 대한 인증 타입. 여기서는 Bearer를 사용. 이후 HTTP 헤더에 prefix로 붙여주는 타입
    private String accessToken;
    private String refreshToken;
    private Long accessTokenExpiresIn;
    private Long refreshTokenExpiresIn;

}
