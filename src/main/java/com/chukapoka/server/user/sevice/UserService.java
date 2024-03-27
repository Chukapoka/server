package com.chukapoka.server.user.sevice;



import com.chukapoka.server.common.authority.jwt.JwtTokenProvider;
import com.chukapoka.server.common.dto.CustomUserDetails;
import com.chukapoka.server.common.dto.TokenDto;
import com.chukapoka.server.common.dto.TokenResponseDto;
import com.chukapoka.server.common.entity.Token;
import com.chukapoka.server.common.enums.Authority;
import com.chukapoka.server.common.enums.EmailType;
import com.chukapoka.server.common.enums.NextActionType;
import com.chukapoka.server.common.enums.ResultType;
import com.chukapoka.server.common.repository.TokenRepository;
import com.chukapoka.server.user.dto.*;
import com.chukapoka.server.user.entity.User;
import com.chukapoka.server.user.repository.UserRepository;
import jakarta.persistence.EntityNotFoundException;
import lombok.AllArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;


@Service
@AllArgsConstructor
public class UserService {
    private final AuthenticationManagerBuilder authenticationManagerBuilder;
    private final JwtTokenProvider jwtTokenProvider;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final TokenRepository tokenRepository;

    /** 이메일 체크 서비스
     * - 이메일이 등록되어 있는지 확인
     * - 등록된 이메일이면 로그인, 등록되지 않은 이메일이면 회원가입으로 처리
     */
    public EmailCheckResponseDto emailCheck(EmailCheckRequestDto emailCheckRequestDto) {
        String email = emailCheckRequestDto.getEmail();
        String emailType = emailCheckRequestDto.getEmailType();
        // 이메일이 이미 등록되어 있는지 확인
        if (userRepository.existsByEmailAndEmailType(email, emailType)) {
            // 이메일이 등록되어 있으면 {login, email} 값 반환
            return new EmailCheckResponseDto(NextActionType.LOGIN.getValue(), email);
        } else {
            // 등록되어 있지않다면 회원가입 {join, email} 값 반환
            return new EmailCheckResponseDto(NextActionType.JOIN.getValue(), email);
        }
    }

    /** 회원가입 처리, 회원가입 성공시 자동로그인(토큰 생성) */
    @Transactional
    public UserResponseDto joinAndLogin(UserRequestDto userRequestDto) {
        // 1. save to user table
        User newUser = saveUser(userRequestDto);
        // 2. make authentication data from user data
        Authentication authentication = getAuthentication(newUser);
        // 3. make token response data from authentication data
        TokenResponseDto tokenResponseDto =  saveToken(authentication); // 사실상 자동 로그인 처리

        return new UserResponseDto(ResultType.SUCCESS, newUser.getEmail(), newUser.getId(), tokenResponseDto);
    }

    /** 로그인 처리, User 데이터 일치시 토큰 생성 */
    @Transactional
    public UserResponseDto login(UserRequestDto userRequestDto) {
        // 1. check to isExist target user data
        User user = findUser(userRequestDto);
        // 2. make authentication data from user data
        Authentication authentication = getAuthentication(user);
        // 3. make token response data from authentication data
        TokenResponseDto tokenResponseDto =  saveToken(authentication);

        return new UserResponseDto(ResultType.SUCCESS, user.getEmail(), user.getId(), tokenResponseDto);
    }

    /**
     * 로그아웃 처리
     * - 클라이언트에서 전달한 Access Token과 Refresh Token을 사용하여 로그아웃 처리
     */
    @Transactional
    public ResultType logout(long userId) {
        // 1. 해당 userId를 기반으로 사용자를 검색
        User user = userRepository.findById(userId).orElseThrow(() -> new EntityNotFoundException("등록되지 않은 유저입니다."));
        // 2. Access Token에서 user ID를 기반으로 Refresh Token 값 가져오기
        Token refreshTokenEntity = tokenRepository.findByKey(String.valueOf(userId))
                    .orElseThrow(() -> new EntityNotFoundException("해당하는 토큰이 존재하지 않습니다."));
        // 3. 저장소에서 Refresh Token 제거
        tokenRepository.delete(refreshTokenEntity);
        return ResultType.SUCCESS;
    }


    /** 토큰 재발급 */
    @Transactional
    public TokenResponseDto reissue(Long userId) {
        // 1. 해당 userId를 기반으로 사용자를 검색(잘못된 userId 요청을 걸러내기 위해)
        User user = userRepository.findById(userId).orElseThrow(() -> new EntityNotFoundException("등록되지 않은 유저입니다."));
        // 2. user ID를 기반으로 Token 데이터 가져오기
        Token token = tokenRepository.findByKey(String.valueOf(userId))
                .orElseThrow(() -> new EntityNotFoundException("해당하는 토큰이 존재하지 않습니다."));
        // 3. Refresh Token 검증(refresh token이 유효하다는 전제이지만, 한번 더 확인)
        if (!jwtTokenProvider.validateToken(token.getRtValue())) {
            throw new RuntimeException("Refresh Token 이 유효하지 않습니다.");
        }
        // 4. make authentication data from user data
        Authentication authentication = getAuthentication(user);
        // 5. make token response data from authentication data
        return saveToken(authentication);
    }

    /** 평문 email, password 데이터로 User 테이블의 모델 생성 */
    public User getNewUser(String email, String password) {
        // BCryptPasswordEncoder를 사용하여 비밀번호를 해시화하여 저장
        String hashedPassword = passwordEncoder.encode(password);
        // 권한을 ROLE_USER로 설정
        String authorities = "ROLE_" + Authority.USER.getAuthority();
        // 새로운 사용자 생성
        return User.builder()
                .email(email)
                .password(hashedPassword)
                .emailType(EmailType.DEFAULT.name())
                .authorities(authorities)
                .build();
    }

    /** User 테이블에 신규유저 데이터 등록, 등록성공시 User 테이블 데이터 반환 */
    public User saveUser(UserRequestDto userRequestDto) {
        String email = userRequestDto.getEmail();
        String password = userRequestDto.getPassword();

        return userRepository.save(getNewUser(email, password));
    }

    /** Request User 데이터와 테이블 데이터 일치여부 확인, 일치시 User 테이블 데이터 반환 */
    public User findUser(UserRequestDto userRequestDto) {
        User user = userRepository.findByEmailAndEmailType(userRequestDto.getEmail(), userRequestDto.getEmailType()).orElseThrow(() -> new EntityNotFoundException("등록되지 않은 유저입니다."));
        if (passwordEncoder.matches(userRequestDto.getPassword(), user.getPassword())) {
            return user;
        } else {
            throw new RuntimeException("비밀번호 불일치");
        }
    }

    /** 유저정보에 따른 Authentication 생성 */
    public Authentication getAuthentication(User user) {
        return new UsernamePasswordAuthenticationToken(
                new CustomUserDetails(user),
                null,
                List.of(
                        new SimpleGrantedAuthority("ROLE_" + Authority.USER.getAuthority())
                )
        );
    }

    /** 유저정보가 담긴 Authentication으로 토큰 생성 및 Token 테이블에 등록 */
    public TokenResponseDto saveToken(Authentication authentication){
        // JWT 토큰 생성
        TokenDto jwtToken = jwtTokenProvider.createToken(authentication);
        Token token = Token.builder()
                .key(authentication.getName())
                .atValue(jwtToken.getAccessToken())
                .rtValue(jwtToken.getRefreshToken())
                .atExpiration(jwtToken.getAtExpiration())
                .rtExpiration(jwtToken.getRtExpiration())
                .build();

        return tokenRepository.save(token).toResponseDto();
    }

}
