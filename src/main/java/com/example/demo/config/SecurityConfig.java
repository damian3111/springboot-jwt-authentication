package com.example.demo.config;

import io.jsonwebtoken.io.Decoders;

import com.example.demo.filter.JWTFilter;
import io.jsonwebtoken.io.Decoders;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.jaas.memory.InMemoryConfiguration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@RequiredArgsConstructor
@Configuration
public class SecurityConfig {

    private final JWTFilter jwtFilter;

    @Bean
    @Order(1)
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .securityMatcher("/getToken", "/login")
                .authorizeHttpRequests(r -> r.requestMatchers("/login").permitAll()
                        .anyRequest().authenticated())
                .formLogin(r -> r.defaultSuccessUrl("/getToken"))
                .build();
    }

    @Bean
    @Order(2)
    SecurityFilterChain securityFilterChain2(HttpSecurity http) throws Exception {
        return http.authorizeHttpRequests(r -> r.anyRequest().authenticated())
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)
                .build();
    }

    @Bean
    InMemoryUserDetailsManager manager(){
        UserDetails userDetails = User.builder()
                .username("asd")
                .password("{noop}asd")
                .roles("user")
                .build();

        return new InMemoryUserDetailsManager(userDetails);
    }
}
