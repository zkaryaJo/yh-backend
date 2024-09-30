package com.tmaxfinai.pjty.controller;

import com.epages.restdocs.apispec.ResourceSnippetParameters;
import com.epages.restdocs.apispec.Schema;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.tmaxfinai.pjty.config.CustomUserDetails;
import com.tmaxfinai.pjty.config.Role;
import com.tmaxfinai.pjty.config.SecurityConfigTest;
import com.tmaxfinai.pjty.dto.oauth.OAuthTokenRequest;
import com.tmaxfinai.pjty.entity.Member;
import com.tmaxfinai.pjty.jwt.JWTFilter;
import com.tmaxfinai.pjty.jwt.JWTUtil;
import com.tmaxfinai.pjty.mapper.MemberMapper;
import com.tmaxfinai.pjty.repository.MemberRepository;
import com.tmaxfinai.pjty.service.KakaoOAuthService;
import com.tmaxfinai.pjty.service.MemberService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.mockito.Answers;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.restdocs.AutoConfigureRestDocs;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.restdocs.payload.JsonFieldType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.client.RestClient;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static com.epages.restdocs.apispec.ResourceDocumentation.resource;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.document;
import static org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.get;
import static org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.post;
import static org.springframework.restdocs.payload.PayloadDocumentation.fieldWithPath;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import({SecurityConfigTest.class})  // TestSecurityConfig 추가
@WebMvcTest(controllers = MemberController.class)
@AutoConfigureRestDocs
class MemberControllerTest {

    @Value("${spring.security.oauth2.client.registration.kakao.client-id}")
    private String clientId;

    @Value("${spring.security.oauth2.client.registration.kakao.client-secret}")
    private String clientSecret;

    @Value("${spring.security.oauth2.client.registration.kakao.redirect-uri}")
    private String redirectUri;

    @MockBean private MemberService memberService;
    @MockBean private KakaoOAuthService kakaoOAuthService;
    @MockBean private JWTUtil jwtUtil;

    @MockBean private MemberMapper memberMapper;
    @MockBean private MemberRepository memberRepository;
    @MockBean(answer = Answers.RETURNS_DEEP_STUBS) private RestClient restClient;
    @Autowired private MockMvc mockMvc;
    @Autowired private ObjectMapper objectMapper;
    @MockBean private JWTFilter jwtFilter;

    @Test
    public void isLogin() throws Exception {

        // HttpOnly 쿠키 설정
        Cookie cookie = new Cookie("accessToken", "test");
        cookie.setHttpOnly(true); // HttpOnly 속성 설정
        cookie.setSecure(false); // HTTPS에서만 전송 (Secure 속성)
        cookie.setPath("/");
        cookie.setMaxAge(7 * 24 * 60 * 60); // 7일간 유효
        cookie.setAttribute("SameSite","None");

        Member member = Member.builder()
                .email("gudwls1029@naver.com")
                .name("형진")
                .birthyear("1992")
                .birthday("1128")
                .ageRange("")
                .phoneNumber("01087216134")
                .role(Role.ROLE_OAUTH2_USER)
                .build();


        // Authentication 객체 생성
        SimpleGrantedAuthority authority = new SimpleGrantedAuthority(member.getRole().name());
        Authentication authentication = new UsernamePasswordAuthenticationToken(member, null, Collections.singletonList(authority));
        // SecurityContext에 인증 정보 설정
        SecurityContextHolder.getContext().setAuthentication(authentication);

//        mockMvc
//                .perform(
//                        get("/member/isLogin")
//                                .with(authentication(authentication))
//                                .characterEncoding("utf-8")
//                                .contentType(MediaType.APPLICATION_JSON)
//                                .accept(MediaType.APPLICATION_JSON)
//                                .cookie(cookie)
//                )
//                .andDo(print())
//                .andExpect(status().isOk())
//                .andDo(document("/member/isLogin",
//                                resource(ResourceSnippetParameters.builder()
//                                        .responseSchema(Schema.schema("MemberIsLoginResponse"))
//                                        .responseFields(
//                                                fieldWithPath("isLogin").type(JsonFieldType.BOOLEAN).description("로그인유무")
//                                        )
//                                        .build())
//                        )
//                );
    }

}