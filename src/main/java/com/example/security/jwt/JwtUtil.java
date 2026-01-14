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

    public boolean validateToken(String token) {
        try {
            Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token);
            return true;
        } catch(ExpiredJwtException e) {
            log.warn("토큰 만료");
            throw e;
        } catch(UnsupportedJwtException e) {
            log.error("잘못된 형식");
        } catch(IllegalArgumentException e) {
            log.error("공백");
        } catch(JwtException e) {
            log.error("검증 불가");
        }

        return false;
    }

    public Claims getClaims(String token) {
        return Jwts.parser()
                   .verifyWith(getSigningKey())
                   .build()
                   .parseSignedClaims(token)
                   .getPayload();
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
