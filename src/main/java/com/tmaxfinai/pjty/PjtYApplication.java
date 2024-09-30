package com.tmaxfinai.pjty;

import com.tmaxfinai.pjty.config.Role;
import com.tmaxfinai.pjty.entity.Member;
import com.tmaxfinai.pjty.repository.MemberRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class PjtYApplication {

    public static void main(String[] args) {
        SpringApplication.run(PjtYApplication.class, args);
    }

    @Bean
    public CommandLineRunner dataLoader(MemberRepository memberRepository){
        return new CommandLineRunner() {
            @Override
            public void run(String... args) throws Exception {
                Member member = Member.builder()
                        .email("gudwls1029@naver.com")
                        .name("형진")
                        .birthyear("1992")
                        .birthday("1128")
                        .ageRange("")
                        .phoneNumber("01087216134")
                        .role(Role.ROLE_OAUTH2_USER)
                        .build();
                memberRepository.save(member);
            }
        };
    }
}
