package com.jwt.authentication.dto;

public record AuthResponse (
        String accessToken,
        String refreshToken
){
}
