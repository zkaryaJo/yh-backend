package com.tmaxfinai.pjty.config;

import com.tmaxfinai.pjty.jwt.JWTFilter;
import com.tmaxfinai.pjty.jwt.JWTUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.client.RestClient;
import org.springframework.web.cors.CorsConfiguration;

import java.util.List;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final AuthenticationConfiguration authenticationConfiguration;
    private final JWTUtil jwtUtil;
    private final OAuth2SuccessHandler oAuth2SuccessHandler;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
//                .csrf(c -> c
//                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
//                )
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

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    public RestClient restClient() {
        return RestClient.create();
    }

}
