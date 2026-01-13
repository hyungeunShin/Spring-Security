package com.example.security.entity;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.List;

@Entity
@Table(name = "users")
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class User implements UserDetails {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String username;

    @Column(nullable = false)
    private String password;

    @Getter
    private int failCount = 0;

    @Getter
    private LocalDateTime lastPasswordChanged;

    @Builder
    public User(String username, String password, LocalDateTime lastPasswordChanged) {
        this.username = username;
        this.password = password;
        this.lastPasswordChanged = lastPasswordChanged;
    }

    @Override
    public String getUsername() {
        return this.username;
    }

    @Override
    public String getPassword() {
        return this.password;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return this.failCount < 5;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return lastPasswordChanged.plusDays(30).isAfter(LocalDateTime.now());
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    public void loginSuccess() {
        this.failCount = 0;
    }

    public int loginFailed() {
        this.failCount++;
        return this.failCount;
    }

    public void changePassword(String password) {
        this.password = password;
        this.failCount = 0;
        this.lastPasswordChanged = LocalDateTime.now();
    }
}
