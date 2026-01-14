package com.example.security.config;

import com.example.security.constant.Constant;
import com.example.security.jwt.JwtUtil;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Map;

@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtUtil jwtUtil;
    private final StringRedisTemplate redisTemplate;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        log.info("=========== JwtAuthenticationFilter ===========");

        String accessToken = resolveAccessToken(request);
        log.info(accessToken);

        if(StringUtils.hasText(accessToken)) {
            String logout = redisTemplate.opsForValue().get(Constant.BLACK_LIST + accessToken);

            log.info("로그아웃 여부: {}", logout);

            if(StringUtils.hasText(logout)) {
                log.warn("이미 로그아웃된 Access Token");
                throw new JwtException("이미 로그아웃된 Access Token");
            }

            try {
                if(jwtUtil.validateToken(accessToken)) {
                    SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(accessToken));
                }
            } catch(ExpiredJwtException e) {
                log.info("Access Token 만료");
                handleTokenReissue(request, response, e);
            } catch(Exception e) {
                log.error("JWT 검증 중 오류 발생: {}", e.getMessage());
                throw new JwtException("유효하지 않은 토큰");
            }
        }

        filterChain.doFilter(request, response);
    }

    private String resolveAccessToken(HttpServletRequest request) {
        String accessToken = request.getHeader(HttpHeaders.AUTHORIZATION);
        if(StringUtils.hasText(accessToken) && accessToken.startsWith("Bearer ")) {
            return accessToken.substring(7);
        }
        return null;
    }

    private void handleTokenReissue(HttpServletRequest request, HttpServletResponse response, ExpiredJwtException e) {
        String refreshToken = getRefreshTokenFromCookie(request);

        if(StringUtils.hasText(refreshToken)) {
            String isLogout = redisTemplate.opsForValue().get(Constant.BLACK_LIST + refreshToken);

            if(StringUtils.hasText(isLogout)) {
                log.warn("이미 로그아웃된 Refresh Token");
                throw new JwtException("이미 로그아웃된 Refresh Token");
            }
        }

        String username = e.getClaims().getSubject();

        String redisKey = Constant.REFRESH_TOKEN_PREFIX + username;
        String redisRefreshToken = redisTemplate.opsForValue().get(redisKey);

        if(StringUtils.hasText(refreshToken) && refreshToken.equals(redisRefreshToken)) {
            log.info("Refresh Token 검증 성공. 새 Access Token 발급");

            String newAccessToken = jwtUtil.generateAccessToken(Map.of("username", username));

            response.setHeader(HttpHeaders.AUTHORIZATION, "Bearer " + newAccessToken);

            SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(newAccessToken));
        } else {
            log.warn("Refresh Token이 일치하지 않거나 Redis에 없음");
            throw new JwtException("Refresh Token이 일치하지 않거나 Redis에 없음");
        }
    }

    private String getRefreshTokenFromCookie(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if(cookies != null) {
            for(Cookie cookie : cookies) {
                if("refreshToken".equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }
}
