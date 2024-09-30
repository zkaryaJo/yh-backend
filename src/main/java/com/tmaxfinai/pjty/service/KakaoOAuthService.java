package com.tmaxfinai.pjty.service;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;

import java.util.Map;

@Service
@RequiredArgsConstructor
public class KakaoOAuthService {

    @Value("${spring.security.oauth2.client.registration.kakao.client-id}")
    private String clientId;

    @Value("${spring.security.oauth2.client.registration.kakao.client-secret}")
    private String clientSecret;

    @Value("${spring.security.oauth2.client.registration.kakao.redirect-uri}")
    private String redirectUri;

    private final RestClient restClient;


    public Map<String, Object> getAccessToken(String code) {
        String tokenUrl = "https://kauth.kakao.com/oauth/token";
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "authorization_code");
        params.add("client_id", clientId);
        params.add("redirect_uri", redirectUri);
        params.add("code", code);

        return restClient.post()
                .uri(tokenUrl)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(params)
                .retrieve()
                .body(Map.class);
    }


    public Map<String, Object> getUserInfo(String accessToken) {
        String userInfoUrl = "https://kapi.kakao.com/v2/user/me";

        return restClient.get()
                .uri(userInfoUrl)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                .retrieve()
                .body(Map.class);
    }
}
