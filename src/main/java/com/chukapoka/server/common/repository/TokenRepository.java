package com.chukapoka.server.common.repository;


import com.chukapoka.server.common.entity.Token;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface TokenRepository extends JpaRepository<Token,Long> {
    Optional<Token> findByKey(String key);
    Optional<Token> findByAtValue(String atValue);

}
