package com.example.gatewayserver.customfilter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.stereotype.Component;

/**
 * JWT 검증 클래스
 */
@Component
public class JwtValidation {
    private static final String SECRET_KEY = "1UQJ5XsXc8ZtKZdfqsJZmrVEyHH4jvoJpmzkEsIjqki4F9HwxWSuwnjuwkKxtcFcNKM9gLhAPm3TfhJxYEEfoNvUQlLvnnE5JrlQ";

    /**
     * JWT Token 검증(디코딩, 파싱 및 위조여부 확인) 메서드
     *
     * @param token 검증하려는 JWT Token
     * @return 검증된 email(subject) 또는 예외
     */
    public String validateAndGetEmail(String token) {
        // parseClaimsJws 메서드가 Base 64로 디코딩 및 파싱
        // 즉, 헤더와 페이로드를 setSigningKey로 넘어온 비밀키를 이용해 서명 후, token의 서명과 비교.
        // 위조되지 않았다면 페이로드(Claims) 리턴, 위조라면 예외를 날림
        Claims claims = Jwts.parser()
                            .setSigningKey(SECRET_KEY)
                            .parseClaimsJws(token)
                            .getBody();

        return claims.getSubject();
    }
}
