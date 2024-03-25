package com.chukapoka.server.tree.dto;

import com.chukapoka.server.common.annotation.ValidEnum;
import com.chukapoka.server.common.enums.TreeType;
import jakarta.validation.constraints.NotBlank;

import lombok.Data;

@Data
public class TreeModifyRequestDto {

    /** 트리에 관련된 것만 수정할것인지 ?*/
    private String title;
    @NotBlank(message = "treeType is null")
    @ValidEnum(enumClass = TreeType.class, message = "TreeType must be MINE or NOT_YET_SEND")
    private String type;
    private String treeBgColor;
    private String groundColor;
    private String treeTopColor;
    private String treeItemColor;
    private String treeBottomColor;


}
