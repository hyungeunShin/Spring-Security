package com.example.security.jwt;

import com.example.security.entity.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
public class JwtUtil {
    private final String secretKey;

    public JwtUtil(@Value("${jwt.secretKey}") String secretKey) {
        this.secretKey = secretKey;
    }

    public String generateAccessToken(User user) {
        return createToken(user, 24 * 60 * 60 * 1000L);
    }

    public String generateRefreshToken(User user) {
        return createToken(user, 7 * 24 * 60 * 60 * 1000L);
    }

    private SecretKey getSigningKey() {
        byte[] keyBytes = secretKey.getBytes(StandardCharsets.UTF_8);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    private String createToken(User user, long expirationMillis) {
        Date now = new Date();

        return Jwts.builder()
                   .header().add("typ", "JWT").and()
                   .issuer("asd")
                   .issuedAt(new Date())
                   .expiration(new Date(now.getTime() + expirationMillis))
                   .subject(user.getUsername())
                   .claim("username", user.getUsername())
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
        } catch(Exception e) {
            return false;
        }
    }

    private Claims getClaims(String token) {
        return Jwts.parser()
                   .verifyWith(getSigningKey())
                   .build()
                   .parseSignedClaims(token)
                   .getPayload();
    }
}
