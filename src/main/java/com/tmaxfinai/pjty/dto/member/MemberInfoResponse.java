package com.tmaxfinai.pjty.dto.member;

import lombok.Data;

@Data
public class MemberInfoResponse {

    private Long id;
    private String email;
    private String name;
    private String gender;
    private String ageRange;
    private String birthday;
    private String birthyear;
    private String phoneNumber;
}
