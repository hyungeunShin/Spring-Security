package com.example.security.config;

import com.example.security.constant.Constant;
import com.example.security.controller.RefreshController;
import com.example.security.jwt.JwtUtil;
import com.example.security.jwt.TokenStatus;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * JWT 인증 필터.
 *
 * 모든 요청에 대해 Authorization 헤더의 Access Token을 검증하는 필터이다.
 * OncePerRequestFilter를 상속하여 요청당 단 한 번만 실행된다.
 *
 * 이 필터는 토큰 재발급 책임을 갖지 않으며,
 * Access Token이 만료되면 즉시 401을 반환하여 프론트엔드에 갱신을 위임한다.
 *
 * <h3>전체 JWT 인증 흐름</h3>
 * <pre>
 * 1. 클라이언트가 API 요청 시 Authorization: Bearer {accessToken} 헤더를 포함한다.
 *
 * 2. 이 필터가 Access Token을 추출하여 다음 순서로 검증한다:
 *    (a) Redis 블랙리스트 조회 → 로그아웃된 토큰이면 401 반환
 *    (b) JwtUtil.validateToken()으로 서명·만료 검증
 *        - VALID   → SecurityContext에 인증 정보 세팅, 요청 계속 진행
 *        - EXPIRED → 401 반환 (프론트엔드가 /refresh 호출해야 함)
 *        - INVALID → 401 반환 (위변조된 토큰)
 *    (c) 토큰이 아예 없으면 인증 없이 요청 진행
 *        → permitAll 엔드포인트는 통과, 나머지는 Spring Security가 403 처리
 *
 * 3. Access Token 만료 시 프론트엔드 처리 흐름:
 *    (a) 401 응답 수신
 *    (b) axios interceptor가 감지하여 POST /refresh 호출 (body: refreshToken)
 *    (c) RefreshController가 Refresh Token 검증 후 새 Access Token + Refresh Token 발급
 *    (d) 프론트엔드가 새 Access Token으로 원래 요청 재시도
 *    (e) Refresh Token도 만료된 경우 → 로그인 페이지로 리다이렉트
 * </pre>
 *
 * @see RefreshController 토큰 갱신 엔드포인트 (POST /refresh)
 * @see JwtUtil 토큰 생성·검증 유틸리티
 * @see TokenStatus 토큰 검증 결과 상태 (VALID, EXPIRED, INVALID)
 */
@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtUtil jwtUtil;
    private final StringRedisTemplate redisTemplate;
    private final ObjectMapper objectMapper;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String accessToken = resolveAccessToken(request);

        if(StringUtils.hasText(accessToken)) {
            // 블랙리스트 확인 (로그아웃된 토큰)
            String isBlacklisted = redisTemplate.opsForValue().get(Constant.BLACK_LIST + accessToken);
            if(StringUtils.hasText(isBlacklisted)) {
                log.warn("블랙리스트 토큰 접근 시도");
                sendError(response, HttpServletResponse.SC_UNAUTHORIZED, "이미 로그아웃된 토큰입니다.");
                return;
            }

            // 토큰 검증
            TokenStatus status = jwtUtil.validateToken(accessToken);

            switch(status) {
                case VALID -> {
                    SecurityContextHolder.getContext().setAuthentication(
                            new JwtAuthenticationToken(accessToken)
                    );
                }
                case EXPIRED -> {
                    log.info("Access Token 만료");
                    sendError(response, HttpServletResponse.SC_UNAUTHORIZED, "Access Token이 만료되었습니다.");
                    return;
                }
                case INVALID -> {
                    log.warn("유효하지 않은 토큰");
                    sendError(response, HttpServletResponse.SC_UNAUTHORIZED, "유효하지 않은 토큰입니다.");
                    return;
                }
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

    private void sendError(HttpServletResponse response, int status, String message) throws IOException {
        response.setStatus(status);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        objectMapper.writeValue(response.getWriter(), Map.of("status", status, "message", message));
    }
}
