package com.jwt.authentication.dto;

public record LoginRequest(
        String username,
        String password
) {
}
