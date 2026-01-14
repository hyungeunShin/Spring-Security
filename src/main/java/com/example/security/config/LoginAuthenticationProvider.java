package com.example.security.config;

import com.example.security.entity.User;
import com.example.security.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.List;

@Slf4j
@RequiredArgsConstructor
public class LoginAuthenticationProvider implements AuthenticationProvider {
    private final PasswordEncoder passwordEncoder;
    private final UserRepository repository;

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        log.info("===========JwtAuthenticationProvider===========");
        log.info("JwtAuthenticationProvider.Authentication: {}", authentication);

        String username = authentication.getName();
        String password = (String) authentication.getCredentials();

        User user = repository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException(username + " -> 존재하지 않는 사용자"));

        if(!user.isAccountNonLocked()) {
            throw new LockedException("비밀번호 5회 초과");
        }

        if(!passwordEncoder.matches(password, user.getPassword())) {
            user.loginFailed();
            repository.save(user);
            throw new BadCredentialsException("비밀번호 틀림");
        }

        user.loginSuccess();

        /*
        public UsernamePasswordAuthenticationToken(Object principal, Object credentials, Collection<? extends GrantedAuthority> authorities) {
            super(authorities);
            this.principal = principal;
            this.credentials = credentials;
            super.setAuthenticated(true);
        }
        */
        return new UsernamePasswordAuthenticationToken(username, null, List.of());
    }
}
