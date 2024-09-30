package com.tmaxfinai.pjty.repository;

import java.util.Optional;

import com.tmaxfinai.pjty.entity.Member;
import org.springframework.data.jpa.repository.JpaRepository;

public interface MemberRepository extends JpaRepository<Member, Long> {
    public Optional<Member> findByEmail(String email);
}
