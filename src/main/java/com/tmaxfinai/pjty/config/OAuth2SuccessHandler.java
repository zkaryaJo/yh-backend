package com.tmaxfinai.pjty.config;

import com.tmaxfinai.pjty.entity.Member;
import com.tmaxfinai.pjty.jwt.JWTUtil;
import com.tmaxfinai.pjty.repository.MemberRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.net.URI;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

@Component
@RequiredArgsConstructor
public class OAuth2SuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final MemberRepository memberRepository;
    private final JWTUtil jwtUtil;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();

        Map kakaoAccountMap = oAuth2User.getAttribute("kakao_account");
        String email = (String)kakaoAccountMap.get("email");
        String name = (String)kakaoAccountMap.get("name");
        String gender = (String)kakaoAccountMap.get("gender");
        String ageRange = (String)kakaoAccountMap.get("age_range");
        String birthday = (String)kakaoAccountMap.get("birthday");
        String birthYear = (String)kakaoAccountMap.get("birthday");
        String phoneNumber = (String)kakaoAccountMap.get("phone_number");

        // 사용자 정보 저장
        if (memberRepository.findByEmail(email).isEmpty()) {
            Member member = new Member();
            member.setEmail(email);
            member.setName(name);
            memberRepository.save(member);
        }

        //create token
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        GrantedAuthority auth = iterator.next();
        String role = auth.getAuthority();
        String token = jwtUtil.createJwt(email, name, "ROLE_"+role, 60*60*1000L);

        // SecurityContext에 인증 정보 설정
        SecurityContextHolder.getContext().setAuthentication(authentication);

        // HttpOnly 쿠키 설정
        Cookie cookie = new Cookie("accessToken", token);
        cookie.setHttpOnly(true); // HttpOnly 속성 설정
        cookie.setSecure(false); // HTTPS에서만 전송 (Secure 속성)
        cookie.setPath("/");
        cookie.setMaxAge(7 * 24 * 60 * 60); // 7일간 유효
        cookie.setAttribute("SameSite","None");
        response.addCookie(cookie);

        response.sendRedirect("http://192.168.0.179:3000?isLoggin=true");
    }


}