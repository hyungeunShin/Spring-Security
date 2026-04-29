package com.example.security.config;

import com.example.security.jwt.JwtUtil;
import com.example.security.property.SecurityProperties;
import com.example.security.repository.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.validation.Validator;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.DelegatingSecurityContextRepository;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;

@Slf4j
@Configuration
@RequiredArgsConstructor
@EnableConfigurationProperties(SecurityProperties.class)
public class SecurityConfig {
    private final SecurityProperties securityProperties;
    private final UserRepository repository;
    private final Validator validator;
    private final JwtUtil jwtUtil;
    private final StringRedisTemplate redisTemplate;
    private final ObjectMapper objectMapper;

    @Bean
    public WebSecurityCustomizer customizer() {
        return web -> {
            WebSecurity.IgnoredRequestConfigurer configurer = web.ignoring()
                    .requestMatchers(PathRequest.toH2Console())
                    .requestMatchers(PathRequest.toStaticResources().atCommonLocations())
                    .requestMatchers("/error");

            securityProperties.getStaticPath().forEach(configurer::requestMatchers);
        };
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable)
            .httpBasic(AbstractHttpConfigurer::disable)
            .formLogin(AbstractHttpConfigurer::disable)
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .logout(AbstractHttpConfigurer::disable);

        http.authorizeHttpRequests(auth -> {
            securityProperties.getPermitAllPath().forEach(path -> {
                log.info("permitAll -> {}", path);
                auth.requestMatchers(path).permitAll();
            });

            auth.anyRequest().authenticated();
        });

        http.addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
        http.addFilterAt(loginAuthenticationFilter(http), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public LoginAuthenticationFilter loginAuthenticationFilter(HttpSecurity http) throws Exception {
        LoginAuthenticationFilter filter = new LoginAuthenticationFilter("/login", authenticationManager(http), validator);
        /*
         * - RequestAttributeSecurityContextRepository:
         *   인증 정보를 현재 요청의 attribute에 저장한다.
         *   같은 요청 안에서만 유효하고, 요청이 끝나면 사라진다.
         *   Spring Security 6 기본값이므로 STATELESS 환경에서는 별도 설정 불필요.
         *
         * - HttpSessionSecurityContextRepository:
         *   인증 정보를 HttpSession에 저장한다.
         *   다음 요청에서도 세션을 통해 인증 상태를 유지할 수 있다.
         *   이걸 추가하면 STATELESS 설정이어도 세션이 생성될 수 있으므로 주의.
         *
         * - DelegatingSecurityContextRepository:
         *   위 두 Repository를 묶어서 위임하는 래퍼.
         *   저장 시 둘 다에 저장하고, 조회 시 순서대로 탐색한다.
         *
         */
//        filter.setSecurityContextRepository(new DelegatingSecurityContextRepository(
//                new RequestAttributeSecurityContextRepository(),
//                new HttpSessionSecurityContextRepository()
//        ));
        filter.setAuthenticationSuccessHandler(loginSuccessHandler());
        filter.setAuthenticationFailureHandler(loginFailureHandler());
        return filter;
    }

    @Bean
    public LoginSuccessHandler loginSuccessHandler() {
        return new LoginSuccessHandler(jwtUtil, redisTemplate);
    }

    @Bean
    public LoginFailureHandler loginFailureHandler() {
        return new LoginFailureHandler();
    }

    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter() {
        return new JwtAuthenticationFilter(jwtUtil, redisTemplate, objectMapper);
    }

    @Bean
    public AuthenticationManager authenticationManager(HttpSecurity http) throws Exception {
        return http.getSharedObject(AuthenticationManagerBuilder.class)
                   .parentAuthenticationManager(null)
                   .authenticationProvider(loginAuthenticationProvider())
                   .build();
    }

    @Bean
    public LoginAuthenticationProvider loginAuthenticationProvider() {
        return new LoginAuthenticationProvider(passwordEncoder(), repository);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
