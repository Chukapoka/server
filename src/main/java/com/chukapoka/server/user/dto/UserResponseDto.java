package com.chukapoka.server.user.dto;

import com.chukapoka.server.common.dto.TokenDto;
import com.chukapoka.server.common.dto.TokenResponseDto;
import com.chukapoka.server.common.enums.ResultType;


import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.security.core.Authentication;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class UserResponseDto {

    private ResultType result; // SUCCESS || ERROR
    private String email; // "xxxx@xxx.xxx"
    private Long userId; // unique_userid
    private TokenResponseDto token; // JWT 토큰

}
