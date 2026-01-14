package com.example.security.config;

import com.example.security.dto.LoginDTO;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validator;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;

import java.io.IOException;
import java.util.Set;

@Slf4j
public class LoginAuthenticationFilter extends AbstractAuthenticationProcessingFilter {
    private final Validator validator;

    protected LoginAuthenticationFilter(String defaultFilterProcessesUrl, AuthenticationManager authenticationManager, Validator validator) {
        super(defaultFilterProcessesUrl, authenticationManager);
        this.validator = validator;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException {
        log.info("=========== LoginAuthenticationFilter ===========");

        ObjectMapper objectMapper = new ObjectMapper();
        LoginDTO dto = objectMapper.readValue(request.getInputStream(), LoginDTO.class);

        Set<ConstraintViolation<LoginDTO>> errors = validator.validate(dto);
        if(!errors.isEmpty()) {
            String errorMessage = errors.iterator().next().getMessage();
            throw new AuthenticationServiceException(errorMessage);
        }

        String username = dto.username();
        String password = dto.password();

        /*
        public UsernamePasswordAuthenticationToken(Object principal, Object credentials) {
            super(null);
            this.principal = principal;
            this.credentials = credentials;
            setAuthenticated(false);
        }

        @Override
        public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
            //...
            super.setAuthenticated(false);
        }
        */
        return getAuthenticationManager().authenticate(new UsernamePasswordAuthenticationToken(username, password));
    }
}
