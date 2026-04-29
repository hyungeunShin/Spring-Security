package com.example.security.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.Map;

@Slf4j
@Component
public class JwtUtil {
    private final String secretKey;
    @Getter
    private final long accessTokenExpireTime;
    @Getter
    private final long refreshTokenExpireTime;

    public JwtUtil(@Value("${jwt.secretKey}") String secretKey,
                   @Value("${jwt.access-token-expire-time}") long accessTokenExpireTime,
                   @Value("${jwt.refresh-token-expire-time}") long refreshTokenExpireTime) {
        this.secretKey = secretKey;
        this.accessTokenExpireTime = accessTokenExpireTime;
        this.refreshTokenExpireTime = refreshTokenExpireTime;
    }

    public String generateAccessToken(Map<String, Object> map) {
        return createToken(map, accessTokenExpireTime);
    }

    public String generateRefreshToken(Map<String, Object> map) {
        return createToken(map, refreshTokenExpireTime);
    }

    private SecretKey getSigningKey() {
        byte[] keyBytes = secretKey.getBytes(StandardCharsets.UTF_8);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    private String createToken(Map<String, Object> map, long expirationMillis) {
        Date now = new Date();

        return Jwts.builder()
                   .header().add("typ", "JWT").and()
                   .issuer("asd")
                   .issuedAt(new Date())
                   .expiration(new Date(now.getTime() + expirationMillis))
                   .subject(map.get("username").toString())
                   .claims(map)
                   .signWith(getSigningKey())
                   .compact();
    }

    /**
     * 토큰 상태를 검증한다.
     * - VALID: 유효한 토큰
     * - EXPIRED: 만료된 토큰 (refresh로 재발급 필요)
     * - INVALID: 위변조, 형식 오류 등
     */
    public TokenStatus validateToken(String token) {
        try {
            Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token);
            return TokenStatus.VALID;
        } catch(ExpiredJwtException e) {
            log.info("토큰 만료");
            return TokenStatus.EXPIRED;
        } catch(JwtException e) {
            log.warn("토큰 검증 실패: {}", e.getMessage());
            return TokenStatus.INVALID;
        } catch(IllegalArgumentException e) {
            log.warn("빈 토큰");
            return TokenStatus.INVALID;
        }
    }

    public Claims getClaims(String token) {
        return Jwts.parser()
                   .verifyWith(getSigningKey())
                   .build()
                   .parseSignedClaims(token)
                   .getPayload();
    }

    public String getUsername(String token) {
        return getClaims(token).getSubject();
    }

    public long getRemainingTime(String token) {
        try {
            Claims claims = getClaims(token);
            Date expiration = claims.getExpiration();

            long now = System.currentTimeMillis();
            long remainTime = expiration.getTime() - now;

            return remainTime > 0 ? remainTime : 0;
        } catch(Exception e) {
            return 0;
        }
    }
}
