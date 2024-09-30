package com.tmaxfinai.pjty.config;

import java.util.ArrayList;
import java.util.Collection;

import com.tmaxfinai.pjty.entity.Member;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

/**
 * 시큐리티를 위한 userDetails
 */
public class CustomUserDetails implements UserDetails {

    private final Member member;

    public CustomUserDetails(Member member) {
        this.member = member;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> collection = new ArrayList<>();

        collection.add(new GrantedAuthority() {
            @Override
            public String getAuthority() {
                return member.getRole().toString();
            }
        });

        return collection;
    }

    @Override
    public String getPassword() {
        return member.getPassword();
    }

    @Override
    public String getUsername() {
        return member.getEmail();
    }

    public String getName() {
        return member.getName();
    }


}