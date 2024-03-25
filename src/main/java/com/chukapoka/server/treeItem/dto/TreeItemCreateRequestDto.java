package com.chukapoka.server.treeItem.dto;

import com.chukapoka.server.tree.entity.Tree;
import com.chukapoka.server.treeItem.entity.TreeItem;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

import java.time.LocalDateTime;

@Data
public class TreeItemCreateRequestDto {

    @NotNull(message = "treeId is null")
    private String treeId;
    @NotBlank(message = "title is null")
    private String title;
    @NotBlank(message = "content is null")
    private String content;
    @NotBlank(message = "treeItemColor is null")
    private String treeItemColor;


    public TreeItem toEntity(Tree tree, TreeItemCreateRequestDto treeItemCreateRequestDto, long userId) {
        return TreeItem.builder()
                .treeId(tree.getTreeId())
                .title(treeItemCreateRequestDto.getTitle())
                .content(treeItemCreateRequestDto.getContent())
                .treeItemColor(treeItemCreateRequestDto.getTreeItemColor())
                .updatedBy(userId)
                .updatedAt(LocalDateTime.now())
                .build();
    }

}


