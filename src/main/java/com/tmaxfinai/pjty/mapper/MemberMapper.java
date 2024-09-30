package com.tmaxfinai.pjty.mapper;

import com.tmaxfinai.pjty.dto.member.MemberInfoResponse;
import com.tmaxfinai.pjty.entity.Member;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.factory.Mappers;

@Mapper(componentModel = "spring")
public interface MemberMapper {
//    MemberMapper INSTANCE = Mappers.getMapper(MemberMapper.class);
    MemberInfoResponse toInfoResponse(Member member);
}
