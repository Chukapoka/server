package com.chukapoka.server.common.authority.jwt;


import com.chukapoka.server.common.dto.CustomUser;
import com.chukapoka.server.common.dto.TokenDto;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;


import java.security.Key;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;


@Slf4j
@Component
public class JwtTokenProvider {

    private static final String AUTHORITIES_KEY = "Authorization";
    private static final String BEARER_TYPE = "Bearer";
    private static final String USER_KEY = "userId";
    // Access Token 만료 시간 상수 (30분)
    private static final long ACCESS_EXPIRATION_MILLISECONDS = 1000 * 60 * 30;
    // Refresh Token 만료 시간 상수 (7일)
    private static final long REFRESH_EXPIRATION_MILLISECONDS = 1000L * 60 * 60 * 24 * 7;
    private final Key key;
    // 비밀 키를 Base64 디코딩한 값으로 초기화
    @Autowired
    public JwtTokenProvider(@Value("${jwt.secret}") String secretKey) {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        this.key = Keys.hmacShaKeyFor(keyBytes);
    }

    /**
     * 사용자 인증 정보를 기반으로 JWT 토큰을 생성하는 메서드
     */

    public TokenDto createToken(Authentication authentication) {
        // 권한 정보를 쉼표로 구분하여 문자열로 변환
        String authorities = authentication
                .getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        Date now = new Date();
        Date accessTokenExpiresIn = new Date(now.getTime() + ACCESS_EXPIRATION_MILLISECONDS);
        Date refreshExpiration = new Date(now.getTime() + REFRESH_EXPIRATION_MILLISECONDS);

        OAuth2User oauth2User = (OAuth2User) authentication.getPrincipal();
        String userId = (String) oauth2User.getAttribute("userId"); // 사용자 ID 가져오기

        // Access Token 생성
        String accessToken = Jwts.builder()
                .setSubject(authentication.getName())
                .claim(AUTHORITIES_KEY, authorities) // 권한
                .claim(USER_KEY, userId)
                .setIssuedAt(now)
                .setExpiration(accessTokenExpiresIn) // 토큰이 만료될시간
                .signWith(key, SignatureAlgorithm.HS256)  // 비밀키, 암호화 알고리즘이름
                .compact();


        // Refresh Token 생성
        String refreshToken = Jwts.builder()
                .setSubject(authentication.getName())
                .claim(AUTHORITIES_KEY, authorities) // 권한
                .claim(USER_KEY,userId)  // user id
                .setIssuedAt(now)
                .setExpiration(refreshExpiration)
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();

        return TokenDto.builder()
                .grantType(BEARER_TYPE)
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .atExpiration(formatDate(accessTokenExpiresIn))
                .rtExpiration(formatDate(refreshExpiration))
                .build();
    }


    /**
     * JWT 토큰에서 사용자 정보를 추출하여 인증 객체를 반환하는 메서드
     */
    public Authentication getAuthentication(String token) {
        Claims claims = parseClaims(token);

        String auth = claims.get(AUTHORITIES_KEY, String.class);
        Long userId = claims.get(USER_KEY, Long.class);

        if (userId == null ||  userId <= 0) {
            throw new RuntimeException("Invalid or empty 'userId' claim in JWT token");
        }

        // 권한 문자열을 분리하여 SimpleGrantedAuthority로 변환
        List<GrantedAuthority> authorities = List.of(auth.split(","))
                .stream()
                .filter(authority -> !authority.isEmpty())
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());

        // UserDetails 객체 생성
        UserDetails principal = new CustomUser(userId, claims.getSubject(), authorities);

        // UsernamePasswordAuthenticationToken을 사용하여 Authentication 객체 반환
        return new UsernamePasswordAuthenticationToken(principal, "", authorities);
    }

    /**
     * JWT 토큰의 유효성을 검증하는 메서드
     */
    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            return true;
        } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {
            log.info("Invalid JWT Token", e);
        } catch (ExpiredJwtException e) {
            log.info("Expired JWT Token", e);
        } catch (UnsupportedJwtException e) {
            log.info("Unsupported JWT Token", e);
        } catch (IllegalArgumentException e) {
            log.info("JWT claims string is empty.", e);
        }
        return false;
    }
    public boolean isTokenExpired(String token) {
        Claims claims = parseClaims(token);
        Date expirationDate = claims.getExpiration();
        return expirationDate == null || !expirationDate.before(new Date());
    }


    /** JWT 토큰에서 클레임(클레임을 포함한 부분)을 추출하는 메서드 */
    private Claims parseClaims(String token) {
        try {
            return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody();
        } catch (ExpiredJwtException e) {
            return e.getClaims();
        }
    }
    /** 토큰 만료기한 날짜 포맷메서드 */
    private String formatDate(Date date) {
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyyMMddHHmmss");
        return dateFormat.format(date);
    }
}