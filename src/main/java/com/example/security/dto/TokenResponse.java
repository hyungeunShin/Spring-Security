package com.example.security.dto;

public record TokenResponse(
        String accessToken,
        String refreshToken
) {}
