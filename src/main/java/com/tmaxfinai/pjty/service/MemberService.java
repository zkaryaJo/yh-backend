package com.tmaxfinai.pjty.service;

import com.tmaxfinai.pjty.dto.member.MemberInfoResponse;
import com.tmaxfinai.pjty.entity.Member;
import com.tmaxfinai.pjty.mapper.MemberMapper;
import com.tmaxfinai.pjty.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class MemberService {

    private final MemberRepository memberRepository;
    private final MemberMapper memberMapper;

    // 회원정보 조회
    public MemberInfoResponse getMemberInfo(String email) {
        Member member = memberRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("회원 정보를 찾을 수 없습니다."));

        return memberMapper.toInfoResponse(member);
    }

    public Member save(Member member) {
        return memberRepository.save(member);
    }

    public Optional<Member> findByEmail(String email) {
        return memberRepository.findByEmail(email);
    }
}
