package com.tmaxfinai.pjty.controller;

import com.tmaxfinai.pjty.config.CustomUserDetails;
import com.tmaxfinai.pjty.dto.member.MemberInfoResponse;
import com.tmaxfinai.pjty.service.MemberService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/member")
@RequiredArgsConstructor
public class MemberController {

    private final MemberService memberService;

    @GetMapping("/me")
    public ResponseEntity<?> info (@AuthenticationPrincipal CustomUserDetails user){

        String email = user.getUsername();
        MemberInfoResponse memberInfoResponse =memberService.getMemberInfo(email);

        return ResponseEntity.ok(memberInfoResponse);
    }

    @GetMapping("/isLogin")
    public ResponseEntity<?> isLogin(@AuthenticationPrincipal CustomUserDetails user){
        return ResponseEntity.ok(Map.of("isLogin",true));
    }

}
