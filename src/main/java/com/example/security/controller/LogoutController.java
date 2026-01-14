package com.example.security.controller;

import com.example.security.constant.Constant;
import com.example.security.jwt.JwtUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;

@Slf4j
@RestController
@RequiredArgsConstructor
public class LogoutController {
    private final JwtUtil jwtUtil;
    private final StringRedisTemplate redisTemplate;

    @DeleteMapping("/logout")
    public void logout(@RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String accessToken,
                       @CookieValue(name = "refreshToken", required = false) String refreshToken) {
        log.info("=========== Logout ===========");

        if(StringUtils.hasText(accessToken) && accessToken.startsWith("Bearer ")) {
            String token = accessToken.substring(7);
            log.info("accessToken: {}", token);
            long accessTokenExpireTime = jwtUtil.getRemainingTime(token);

            if(accessTokenExpireTime > 0) {
                redisTemplate.opsForValue().set(Constant.BLACK_LIST + token, "logout", Duration.ofMillis(accessTokenExpireTime));
            }
        }

        if(StringUtils.hasText(refreshToken)) {
            long refreshTokenExpireTime = jwtUtil.getRemainingTime(refreshToken);
            log.info(refreshToken);

            if(refreshTokenExpireTime > 0) {
                redisTemplate.opsForValue().set(Constant.BLACK_LIST + refreshToken, refreshToken, Duration.ofMillis(refreshTokenExpireTime));
            }
        }

        SecurityContextHolder.clearContext();
    }
}
