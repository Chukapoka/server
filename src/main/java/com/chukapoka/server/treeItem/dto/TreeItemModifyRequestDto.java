package com.chukapoka.server.treeItem.dto;

import lombok.Data;

@Data
public class TreeItemModifyRequestDto {

    private String title;
    private String content;
    private String treeItemColor;
}
