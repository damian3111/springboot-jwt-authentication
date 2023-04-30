package com.example.demo.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.impl.DefaultClaims;
import io.jsonwebtoken.impl.DefaultHeader;
import io.jsonwebtoken.io.Encoder;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Service
public class TokenService {

    @Value("${application.security.key}")
    private String key;

    public String getToken(){

        DefaultClaims defaultClaims = new DefaultClaims();
        defaultClaims.put("asd", "asd");

        long expiration = 1000 * 60 * 50;

        Map<String, Object> header = new HashMap<>();
        header.put("blalblagbllabl", "blalbalbalba");
        header.put("blalbalbalba", "blalbalbalba");

        String jwt = Jwts.builder()
                .setHeader(header)
                .setSubject("mySubject")
                .setClaims(defaultClaims)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(encoder(), SignatureAlgorithm.HS256)
                .compact();

        return jwt;
    }

    public Key encoder(){

        byte[] decode = Decoders.BASE64.decode(key);
        return Keys.hmacShaKeyFor(decode);
    }
}
