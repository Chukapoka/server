package com.chukapoka.server.tree.dto;

import com.chukapoka.server.common.annotation.ValidEnum;
import com.chukapoka.server.common.enums.TreeType;
import com.chukapoka.server.tree.entity.Tree;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

import java.util.UUID;

@Data
public class TreeCreateRequestDto {
    @NotBlank(message = "title is null")
    private String title;
    @NotBlank(message = "treeType is null")
    @ValidEnum(enumClass = TreeType.class, message = "TreeType must be MINE or NOT_YET_SEND")
    private String type;
    private String treeBgColor;
    private String groundColor;
    private String treeTopColor;
    private String treeItemColor;
    private String treeBottomColor;
    // 클라이언트에서는 입력받을 필요없음 ( TreeServicelmpl.createTree 에서 처리 )

    /** Create Tree Build*/
    public Tree toEntity(TreeCreateRequestDto treeRequestDto, long userId) {
        UUID linkId = UUID.randomUUID();
        UUID sendId = UUID.randomUUID();
        return Tree.builder()
                .title(treeRequestDto.title)
                .type(treeRequestDto.type)
                .linkId(linkId + "-link-"+ userId )
                .sendId(sendId + "-send-"+ userId)
                .treeBgColor(treeRequestDto.treeBgColor)
                .groundColor(treeRequestDto.groundColor)
                .treeTopColor(treeRequestDto.treeTopColor)
                .treeItemColor(treeRequestDto.treeItemColor)
                .treeBottomColor(treeRequestDto.treeBottomColor)
                .updatedBy(userId)
                .build();

    }
}