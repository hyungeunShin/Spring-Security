package com.example.security.event;

import com.example.security.entity.User;
import com.example.security.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;

@Component
@RequiredArgsConstructor
public class InitEvent {
    private final UserRepository repository;
    private final PasswordEncoder passwordEncoder;

    @EventListener(ApplicationReadyEvent.class)
    public void init() {
        repository.save(new User("aaa", passwordEncoder.encode("123"), LocalDateTime.now()));
        repository.save(new User("bbb", passwordEncoder.encode("123"), LocalDateTime.now().minusDays(32)));
    }
}
