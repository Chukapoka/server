package com.chukapoka.server.user.repository;



import com.chukapoka.server.user.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {


    /**
     * Email로 로그인을 하기 때문에 중복 가입 방지와 존재여부를 파악하는 메서드를 추가
     */
    // CustomUser에서 email찾기
    Optional<User> findByEmail(String email);

    Optional<User> findByEmailAndEmailType(String email, String emailType);

    Optional<User> findById(Long id);

    // 이메일이 등록되어있는지 이메일과 이메일타입 확인
    boolean existsByEmailAndEmailType(String email, String emailType);


}
