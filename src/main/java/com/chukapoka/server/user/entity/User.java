package com.chukapoka.server.user.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.security.core.userdetails.UserDetails;


import java.time.LocalDateTime;
import java.util.Map;


@Entity
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
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

    @Column(nullable = false, unique = true)
    private String email;

    @Column(nullable = false)
    private String emailType;

    @Column(nullable = false)
    private String password;

    @Column(nullable = false)
    private LocalDateTime updatedAt;

    @Transient
    private String role; // 권한 ROLE_USER || ROLE_ADMIN



}
