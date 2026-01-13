package com.example.security.dto;

import jakarta.validation.constraints.NotBlank;

public record LoginDTO(
        @NotBlank(message = "아이디는 필수")
        String username,

        @NotBlank(message = "패스워드는 필수")
        String password) {
}
