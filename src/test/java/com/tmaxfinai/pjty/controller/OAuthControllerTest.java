package com.tmaxfinai.pjty.controller;

import com.epages.restdocs.apispec.ResourceSnippetParameters;
import com.epages.restdocs.apispec.Schema;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.tmaxfinai.pjty.config.Role;
import com.tmaxfinai.pjty.config.SecurityConfigTest;
import com.tmaxfinai.pjty.dto.oauth.OAuthTokenRequest;
import com.tmaxfinai.pjty.entity.Member;
import com.tmaxfinai.pjty.jwt.JWTUtil;
import com.tmaxfinai.pjty.mapper.MemberMapper;
import com.tmaxfinai.pjty.repository.MemberRepository;
import com.tmaxfinai.pjty.service.KakaoOAuthService;
import com.tmaxfinai.pjty.service.MemberService;
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
import org.springframework.restdocs.payload.JsonFieldType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static com.epages.restdocs.apispec.ResourceDocumentation.resource;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.document;
import static org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.post;
import static org.springframework.restdocs.payload.PayloadDocumentation.fieldWithPath;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import({SecurityConfigTest.class})  // TestSecurityConfig 추가
@WebMvcTest(controllers = OAuthController.class)
@AutoConfigureRestDocs
public class OAuthControllerTest {

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

    @Test
    public void token() throws Exception {

        OAuthTokenRequest oAuthTokenRequest = new OAuthTokenRequest();
        oAuthTokenRequest.setProvider("kakao");
        oAuthTokenRequest.setCode("58noWP5PNPdCTpzoPHLQ-wSQHTphBdhlll6Jm2eM7t242l8KB2BSKAAAAAQKPCRZAAABkif-qZTo6jj-qNQmaA");

        Member member = Member.builder()
                .email("gudwls1029@naver.com")
                .name("형진")
                .birthyear("1992")
                .birthday("1128")
                .ageRange("")
                .phoneNumber("01087216134")
                .role(Role.ROLE_OAUTH2_USER)
                .build();

        Map<String, Object> tokenMap = Map.of(
                "access_token",""
        );


        given(kakaoOAuthService.getAccessToken(any(String.class))).willReturn(tokenMap);

        Map kakaoAccountMap = Map.of(
                "email","gudwls1029@naver.com",
                "name","",
                "gender","",
                "age_range","",
                "birthday","",
                "birthyear","",
                "phone_number",""
        );

        Map userInfo = new HashMap<>();
        userInfo.put("kakao_account", kakaoAccountMap);


        given(kakaoOAuthService.getUserInfo(any(String.class))).willReturn(userInfo);

        given(memberService.findByEmail("email")).willReturn(Optional.of(member));
        given(memberService.save(any(Member.class))).willReturn(member);

        given(jwtUtil.createJwt(any(String.class), any(String.class), any(String.class), any(Long.class))).willReturn("accessToken");

        mockMvc
                .perform(
                        post("/oauth/token")
//                                .with(csrf())
                                .content(objectMapper.writeValueAsString(oAuthTokenRequest))
                                .characterEncoding("utf-8")
                                .contentType(MediaType.APPLICATION_JSON)
                                .accept(MediaType.APPLICATION_JSON)
                )
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andDo(print())
                .andDo(document("/yh/oauth/token",
                                resource(ResourceSnippetParameters.builder()
                                        .requestSchema(Schema.schema("OAuthTokenRequest"))
                                        .requestFields(
                                                fieldWithPath("provider").type(JsonFieldType.STRING).description("OAUTH 제공업체 ex)kakao, naver").attributes(),
                                                fieldWithPath("code").type(JsonFieldType.STRING).description("OAUTH에서 인증받은 code")
                                        )
                                        .responseSchema(Schema.schema("OAuthTokenResponse"))
                                        .responseFields(
                                                fieldWithPath("accessToken").type(JsonFieldType.STRING).description("사용자 ID")
                                        )
                                        .build())
                        )
                );

    }
}