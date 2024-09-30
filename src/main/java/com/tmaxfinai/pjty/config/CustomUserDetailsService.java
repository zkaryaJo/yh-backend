package com.tmaxfinai.pjty.config;

import com.tmaxfinai.pjty.entity.Member;
import com.tmaxfinai.pjty.repository.MemberRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final MemberRepository memberRepository;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {

        Member member = memberRepository.findByEmail(email).orElseThrow();
        if(member != null) {
            return new CustomUserDetails(member);
        }
        return null;
    }
}