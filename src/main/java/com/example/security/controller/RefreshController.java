package com.example.security.controller;

import com.example.security.constant.Constant;
import com.example.security.dto.RefreshRequest;
import com.example.security.dto.TokenResponse;
import com.example.security.jwt.JwtUtil;
import com.example.security.jwt.TokenStatus;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;
import java.util.Map;

/**
 * 토큰 갱신 컨트롤러.
 *
 * 프론트가 401(Access Token 만료)을 받으면 이 엔드포인트를 호출한다.
 * Refresh Token을 검증하고, 유효하면 새 Access Token + 새 Refresh Token을 발급한다.
 */
@Slf4j
@RestController
@RequiredArgsConstructor
public class RefreshController {
    private final JwtUtil jwtUtil;
    private final StringRedisTemplate redisTemplate;

    @PostMapping("/refresh")
    public ResponseEntity<TokenResponse> refresh(@Valid @RequestBody RefreshRequest request) {
        String refreshToken = request.refreshToken();

        // 1. 블랙리스트 확인
        String isBlacklisted = redisTemplate.opsForValue().get(Constant.BLACK_LIST + refreshToken);
        if(StringUtils.hasText(isBlacklisted)) {
            log.warn("블랙리스트 Refresh Token으로 갱신 시도");
            return ResponseEntity.status(401).build();
        }

        // 2. Refresh Token 유효성 검증
        TokenStatus status = jwtUtil.validateToken(refreshToken);
        if(status != TokenStatus.VALID) {
            log.warn("유효하지 않은 Refresh Token: {}", status);
            return ResponseEntity.status(401).build();
        }

        // 3. Redis에 저장된 Refresh Token과 비교
        String username = jwtUtil.getUsername(refreshToken);
        String storedToken = redisTemplate.opsForValue().get(Constant.REFRESH_TOKEN_PREFIX + username);
        if(!refreshToken.equals(storedToken)) {
            log.warn("Refresh Token 불일치 (username={})", username);
            return ResponseEntity.status(401).build();
        }

        // 4. 새 토큰 발급
        Map<String, Object> claims = Map.of("username", username);
        String newAccessToken = jwtUtil.generateAccessToken(claims);
        String newRefreshToken = jwtUtil.generateRefreshToken(claims);

        // 5. Redis에 새 Refresh Token 저장 (기존 것 덮어쓰기)
        redisTemplate.opsForValue().set(
                Constant.REFRESH_TOKEN_PREFIX + username,
                newRefreshToken,
                Duration.ofMillis(jwtUtil.getRefreshTokenExpireTime())
        );

        log.info("토큰 갱신 완료 (username={})", username);

        return ResponseEntity.ok(new TokenResponse(newAccessToken, newRefreshToken));
    }
}
