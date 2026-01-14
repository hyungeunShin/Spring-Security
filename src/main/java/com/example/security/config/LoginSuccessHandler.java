package com.example.security.config;

import com.example.security.constant.Constant;
import com.example.security.dto.LoginResponseDTO;
import com.example.security.entity.User;
import com.example.security.jwt.JwtUtil;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.web.server.Cookie;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;

@Slf4j
public class LoginSuccessHandler implements AuthenticationSuccessHandler {
    private final JwtUtil jwtUtil;
    private final StringRedisTemplate redisTemplate;
    private final ObjectMapper objectMapper;

    public LoginSuccessHandler(JwtUtil jwtUtil, StringRedisTemplate redisTemplate) {
        this.jwtUtil = jwtUtil;
        this.redisTemplate = redisTemplate;
        this.objectMapper = new ObjectMapper();
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        log.info("=========== LoginSuccessHandler.onAuthenticationSuccess ===========");

        User user = (User) authentication.getDetails();

        log.info("{}", user);

        Map<String, Object> map = Map.of("username", user.getUsername());

        String accessToken = jwtUtil.generateAccessToken(map);
        String refreshToken = jwtUtil.generateRefreshToken(map);

        redisTemplate.opsForValue().set(
                Constant.REFRESH_TOKEN_PREFIX + authentication.getName(),
                refreshToken,
                Duration.ofMillis(jwtUtil.getRefreshTokenExpireTime())
        );

        response.setHeader(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken);
        response.addHeader(HttpHeaders.SET_COOKIE, addCookie(refreshToken).toString());

        response.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
        response.setHeader(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());

        LoginResponseDTO dto;
        if(!user.isCredentialsNonExpired()) {
            dto = new LoginResponseDTO("/change-password", "비밀번호 변경한지 30일 초과");
        } else {
            dto = new LoginResponseDTO("/main", "");
        }

        String result = objectMapper.writeValueAsString(dto);
        response.getWriter().write(result);
    }

    private ResponseCookie addCookie(String refreshToken) {
        return ResponseCookie.from("refreshToken", refreshToken)
                             .httpOnly(true)
                             //.secure(true)
                             .path("/")
                             .maxAge(jwtUtil.getRefreshTokenExpireTime() / 1000)
                             .sameSite(Cookie.SameSite.LAX.name())
                             .build();
    }
}
