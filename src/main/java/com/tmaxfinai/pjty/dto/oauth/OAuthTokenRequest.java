package com.tmaxfinai.pjty.dto.oauth;

import lombok.Data;

@Data
public class OAuthTokenRequest {
    String provider;
    String code;
}
