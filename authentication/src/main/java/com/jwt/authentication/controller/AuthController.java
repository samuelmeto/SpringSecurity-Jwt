package com.jwt.authentication.controller;

import com.jwt.authentication.dto.AuthResponse;
import com.jwt.authentication.dto.LoginRequest;
import com.jwt.authentication.dto.RefreshRequest;
import com.jwt.authentication.dto.RegisterRequest;
import com.jwt.authentication.model.RefreshToken;
import com.jwt.authentication.service.JwtService;
import com.jwt.authentication.service.RefreshTokenService;
import com.jwt.authentication.service.UserService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("api/v1/")
public class AuthController {

    private final UserService userService;
    private final DaoAuthenticationProvider daoAuthenticationProvider;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;

    public AuthController(UserService userService, DaoAuthenticationProvider daoAuthenticationProvider, JwtService jwtService, RefreshTokenService refreshTokenService) {
        this.userService = userService;
        this.daoAuthenticationProvider = daoAuthenticationProvider;
        this.jwtService = jwtService;
        this.refreshTokenService = refreshTokenService;
    }


    @PostMapping("register")
    public ResponseEntity<String> register(@RequestBody RegisterRequest request) {
        try {
            String result = userService.register(request);
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            return new ResponseEntity<>("can not registered.", HttpStatus.BAD_REQUEST);
        }
    }

    @PostMapping("login")
    public ResponseEntity<AuthResponse> login(@RequestBody LoginRequest request) {

        Authentication authentication = daoAuthenticationProvider.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.username(),
                        request.password()
                )
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);

        String jwtToken = jwtService.generateToken(authentication);
        String refreshToken = refreshTokenService.createRefreshToken(request.username()).getToken();

        AuthResponse response = new AuthResponse(jwtToken, refreshToken);

        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    @PostMapping("refreshToken")
    public ResponseEntity<?> refreshJwtToken(@RequestBody RefreshRequest request) {

        RefreshToken token = refreshTokenService.findByToken(request.token()).orElseThrow(
                () -> new UsernameNotFoundException("token not found.")
        );

        if (refreshTokenService.verifyExpiration(token)) {
            String accessToken = jwtService.generateTokenWithUsername(token.getUser().getUsername());
            return new ResponseEntity<>(new AuthResponse(accessToken, token.getToken()), HttpStatus.OK);
        }
        return new ResponseEntity<>("refresh token is expired.",HttpStatus.BAD_REQUEST);
    }

}
