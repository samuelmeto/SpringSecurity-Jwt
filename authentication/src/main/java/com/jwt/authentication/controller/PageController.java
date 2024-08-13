package com.jwt.authentication.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1")
public class PageController {

    @PreAuthorize("hasRole('USER')")
    @GetMapping("user")
    public String getUserProfile(){
        return SecurityContextHolder.getContext().getAuthentication().getName();
    }
}
