package com.jwt.authentication.dto;

public record RegisterRequest(
        String username,
        String password,
        String firstName,
        String lastName
) {
}
