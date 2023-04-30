package com.example.demo.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.security.Principal;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@RequiredArgsConstructor
@Component
public class JWTFilter extends OncePerRequestFilter{

    @Value("${application.security.key}")
    private String key;
    String[] blackList = new String[]{"/getToken", "/favicon.ico", "/login"};

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        String token = obtainToken(request);

        Jws<Claims> claimsJws = Jwts.parserBuilder()
                .setSigningKey(key)
                .build().parseClaimsJws(token);

        User user = new User("jan", "kowal", Arrays.asList(new SimpleGrantedAuthority("USER")));

        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());

        SecurityContextHolder.getContext().setAuthentication(authenticationToken);

        filterChain.doFilter(request, response);

    }

    private String obtainToken(HttpServletRequest request) {

        String authorization = request.getHeader("Authorization");
        return authorization.substring(7);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {

        return Stream.of(blackList).anyMatch(r -> r.equals(request.getRequestURI()));
    }
}
