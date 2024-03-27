package com.chukapoka.server.user.entity;

import jakarta.persistence.*;
import lombok.*;
import org.springframework.security.core.userdetails.UserDetails;


import java.time.LocalDateTime;


@Entity
@Data
@AllArgsConstructor
@NoArgsConstructor
@Table(name = "tb_user")
public class User {

    /**
     * Security Test를 위한 사용자 도메인
     * 이메일, 비밀번호, 권한만을 가지고 있으며, 이메일로 로그인하도록 만들 예정
     */
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "userId")
    private Long id;

    @Column(nullable = false, name = "email", unique = true)
    private String email;

    @Column(nullable = false, name = "emailType")
    private String emailType;

    @Column(nullable = false, name = "password")
    private String password;

    @Column(nullable = false, name = "updateAt")
    private LocalDateTime updatedAt;

    @Column
    private String authorities; // 권한 ROLE_USER || ROLE_ADMIN

    @Builder
    public User(String email, String password, String emailType,String authorities)  {
        this.email = email;
        this.password = password;
        this.emailType = emailType;
        this.authorities = authorities;
        this.updatedAt = LocalDateTime.now();
    }



}
