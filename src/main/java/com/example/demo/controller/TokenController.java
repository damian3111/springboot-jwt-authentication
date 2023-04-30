package com.example.demo.controller;

import com.example.demo.service.TokenService;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RequiredArgsConstructor
@RestController
public class TokenController {

    private final TokenService tokenService;

    @GetMapping("/getToken")
    public String getToken(Authentication authentication){

        return tokenService.getToken();
    }

    @GetMapping("/res")
    public ResponseEntity<String> getResource(Authentication authentication){
        return ResponseEntity.ok("Hello " + authentication.getName());
    }
}
