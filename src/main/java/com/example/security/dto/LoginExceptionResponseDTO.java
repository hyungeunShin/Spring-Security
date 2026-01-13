package com.example.security.dto;

import org.springframework.http.HttpStatus;

public record LoginExceptionResponseDTO(String errorMessage, HttpStatus status) {
}
