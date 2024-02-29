package com.chukapoka.server.treeItem.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class TreeItemDetailResponseDto {

    /** 트리 아이템 상세정보 */
    private String id;
    private String treeId;
    private String title;
    private String content;
    private String treeItemColor;
    private Long updatedBy;
    private LocalDateTime updatedAt;

}
