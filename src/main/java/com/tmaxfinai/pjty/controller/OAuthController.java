package com.tmaxfinai.pjty.controller;

import com.tmaxfinai.pjty.config.Role;
import com.tmaxfinai.pjty.dto.oauth.OAuthTokenResponse;
import com.tmaxfinai.pjty.entity.Member;
import com.tmaxfinai.pjty.jwt.JWTUtil;
import com.tmaxfinai.pjty.service.KakaoOAuthService;
import com.tmaxfinai.pjty.service.MemberService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;

import java.util.Collections;
import java.util.Map;

@RestController
@RequestMapping("/oauth")
@RequiredArgsConstructor
public class OAuthController {

    @Value("${spring.security.oauth2.client.registration.kakao.redirect-uri}")
    private String redirectUri;

    private final MemberService memberService;
    private final JWTUtil jwtUtil;

    private final KakaoOAuthService kakaoOAuthService;

    @PostMapping("/token")
    public ResponseEntity<?> token(@RequestBody Map param, HttpServletResponse response) {
        try {

            Map tokenResponse,userInfo = null;

            if("kakao".equals(param.get("provider"))){
                // 액세스 토큰 요청
                tokenResponse = kakaoOAuthService.getAccessToken(""+param.get("code"));
                // 액세스 토큰 추출
                String accessToken = (String) tokenResponse.get("access_token");
                userInfo = kakaoOAuthService.getUserInfo(accessToken);
            }

            Map kakaoAccountMap = (Map)userInfo.get("kakao_account");
            String email = (String)kakaoAccountMap.get("email");
            String name = (String)kakaoAccountMap.get("name");
            String gender = (String)kakaoAccountMap.get("gender");
            String ageRange = (String)kakaoAccountMap.get("age_range");
            String birthday = (String)kakaoAccountMap.get("birthday");
            String birthYear = (String)kakaoAccountMap.get("birthyear");
            String phoneNumber = (String)kakaoAccountMap.get("phone_number");

            Member member = memberService.findByEmail(email).orElse(null);
            // 사용자 정보 저장
            if (member == null) {

                member = Member.builder()
                        .email(email)
                        .name(name)
                        .gender(gender)
                        .birthday(birthday)
                        .birthyear(birthYear)
                        .phoneNumber(phoneNumber)
                        .ageRange(ageRange)
                        .role(Role.ROLE_OAUTH2_USER)
                        .build();
                memberService.save(member);
            }

            String token = jwtUtil.createJwt(email, name, Role.ROLE_OAUTH2_USER.name(), 60*60*1000L);

            // Authentication 객체 생성
            SimpleGrantedAuthority authority = new SimpleGrantedAuthority(member.getRole().name());
            Authentication authentication = new UsernamePasswordAuthenticationToken(member, null, Collections.singletonList(authority));
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

            OAuthTokenResponse oAuthTokenResponse = new OAuthTokenResponse();
            oAuthTokenResponse.setAccessToken(token);

            return ResponseEntity.ok(oAuthTokenResponse);
        } catch (Exception e) {
            return ResponseEntity.status(500).body("에러 발생: " + e.getMessage());
        }
    }

    

    @PostMapping("/tokenTest")
    public ResponseEntity<?> tokenTest(@RequestBody Map param, HttpServletResponse response) {
        try {

            Map tokenResponse = null;
            String email = "gudwls1029@naver.com";
            String name = "조형진";
            String gender ="";
            String birthday = "1128";
            String birthYear = "2020";
            String phoneNumber = "01087216134";
            String ageRange = "30";

            Member member = memberService.findByEmail(email).orElse(null);
            // 사용자 정보 저장
            if (member == null) {

                member = Member.builder()
                        .email(email)
                        .name(name)
                        .gender(gender)
                        .birthday(birthday)
                        .birthyear(birthYear)
                        .phoneNumber(phoneNumber)
                        .ageRange(ageRange)
                        .role(Role.ROLE_OAUTH2_USER)
                        .build();
                memberService.save(member);
            }

            String token = jwtUtil.createJwt(email, name, Role.ROLE_OAUTH2_USER.name(), 60*60*1000L);

            // Authentication 객체 생성
            SimpleGrantedAuthority authority = new SimpleGrantedAuthority(member.getRole().name());
            Authentication authentication = new UsernamePasswordAuthenticationToken(member, null, Collections.singletonList(authority));
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

            return ResponseEntity.ok(Map.of("accessToken",token));
        } catch (Exception e) {
            return ResponseEntity.status(500).body("에러 발생: " + e.getMessage());
        }
    }

}
