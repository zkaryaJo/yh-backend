package com.tmaxfinai.pjty.jwt;

import com.tmaxfinai.pjty.config.CustomUserDetails;
import com.tmaxfinai.pjty.config.Role;
import com.tmaxfinai.pjty.entity.Member;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

@RequiredArgsConstructor
public class JWTFilter extends OncePerRequestFilter {

    private final JWTUtil jwtUtil;
    private static final List<String> EXCLUDED_URLS = List.of(
            "/yh/",
            "/yh/swagger.html",
            "/yh/swagger-ui.html",
            "/yh/**",
            "/favicon.ico",
            "/oauth/**",
            "/api/v1/auth/**",
            "/oauth2/**",
            "/h2-console/**",
            "/member/isLogin"
    );

    private boolean isExcluded(String requestURI) {
        return EXCLUDED_URLS.stream().anyMatch(uri -> {
            if (uri.endsWith("/**")) {
                String baseUri = uri.substring(0, uri.length() - 3);
                return requestURI.startsWith(baseUri);
            } else {
                return requestURI.equals(uri);
            }
        });
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        // 제외할 URL인지 확인하여 필터링 생략
        if (isExcluded(request.getRequestURI())) {
            filterChain.doFilter(request, response);
            return;
        }
        String token = "";
        // request에서 Authorization 헤더를 찾음
        String authorization = request.getHeader("Authorization");

        if (authorization != null && authorization.startsWith("Bearer ")) {
            token = authorization.substring(7); // "Bearer " 이후의 토큰 값
        } else {
            if (request.getCookies() != null) {
                for (Cookie item : request.getCookies()) {
                    String name = item.getName();
                    item.setMaxAge(0);
                    if ("accessToken".equals(name)) {
                        token = item.getValue();
                        break;
                    }
                }
            }
        }

        if ("".equals(token)) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            // 토큰에서 정보 추출 및 유효성 검증
            String email = jwtUtil.getEmail(token);
            String name = jwtUtil.getName(token);
            String role = jwtUtil.getRole(token);

            Member member = Member.builder()
                    .email(email)
                    .name(name)
                    .role(Role.valueOf(role))
                    .build();

            CustomUserDetails customUserDetails = new CustomUserDetails(member);

            Authentication authToken = new UsernamePasswordAuthenticationToken(
                    customUserDetails, null, customUserDetails.getAuthorities()
            );

            SecurityContextHolder.getContext().setAuthentication(authToken);

        } catch (ExpiredJwtException e) {
            // 토큰이 만료된 경우 처리
            System.out.println("Token expired");
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json;charset=UTF-8");
            response.getWriter().write("{\"error\":\"토큰이 만료되었습니다.\"}");

            // HttpOnly 쿠키 설정
            Cookie cookie = new Cookie("accessToken", "");
            cookie.setHttpOnly(true); // HttpOnly 속성 설정
            cookie.setSecure(false); // HTTPS에서만 전송 (Secure 속성)
            cookie.setPath("/");
            cookie.setMaxAge(0); // 무효
            cookie.setAttribute("SameSite","None");
            response.addCookie(cookie);

            return;
        } catch (JwtException | IllegalArgumentException e) {
            // 유효하지 않은 토큰인 경우 처리
            System.out.println("Invalid token");
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json;charset=UTF-8");
            response.getWriter().write("{\"error\":\"유효하지 않은 토큰입니다.\"}");

            // HttpOnly 쿠키 설정
            Cookie cookie = new Cookie("accessToken", "");
            cookie.setHttpOnly(true); // HttpOnly 속성 설정
            cookie.setSecure(false); // HTTPS에서만 전송 (Secure 속성)
            cookie.setPath("/");
            cookie.setMaxAge(0); // 무효
            cookie.setAttribute("SameSite","None");
            response.addCookie(cookie);

            return;
        }

        filterChain.doFilter(request, response);
    }
}
