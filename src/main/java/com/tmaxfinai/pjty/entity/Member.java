package com.tmaxfinai.pjty.entity;

import com.tmaxfinai.pjty.config.Role;
import jakarta.persistence.*;
import lombok.*;

@Entity
@Table
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Member {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String email;
    private String name;
    private String gender;
    private String ageRange;
    private String birthday;
    private String birthyear;
    private String phoneNumber;
    private String password;
    @Enumerated(EnumType.STRING)
    private Role role;
}
