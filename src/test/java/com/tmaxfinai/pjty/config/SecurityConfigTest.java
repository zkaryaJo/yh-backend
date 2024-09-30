package com.tmaxfinai.pjty.config;

import com.tmaxfinai.pjty.jwt.JWTFilter;
import com.tmaxfinai.pjty.jwt.JWTUtil;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;

import java.util.List;

@TestConfiguration

public class SecurityConfigTest {

    @Autowired
    private JWTUtil jwtUtil;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .cors(cors -> cors.configurationSource(request -> {
                    CorsConfiguration config = new CorsConfiguration();
                    config.setAllowedOrigins(
                            List.of("https://ybrother.co.kr",
                                    "http://ybrother.co.kr",
                                    "http://127.0.0.1:3000",
                                    "http://192.168.0.18:3000",
                                    "http://192.168.0.179:3000",
                                    "http://localhost:3000")
                    );
                    config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
                    config.setAllowCredentials(true);
                    config.setAllowedHeaders(List.of("*"));
                    return config;
                }))
                .csrf(AbstractHttpConfigurer::disable)
                .headers(header -> header.frameOptions(HeadersConfigurer.FrameOptionsConfig::disable))
                .authorizeHttpRequests(a -> a
                        .requestMatchers("/yh/**", "/yh/swagger.html","/favicon.ico").permitAll() // swagger
                        .requestMatchers("/oauth/**", "/api/v1/auth/**", "/oauth2/**", "/member/isLogin", "/h2-console/**").permitAll()
                        .anyRequest().authenticated()
                )
                .logout(l -> l
                        .logoutSuccessUrl("/").permitAll()
                )
                .addFilterBefore(new JWTFilter(jwtUtil), UsernamePasswordAuthenticationFilter.class)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        return http.build();
    }
}