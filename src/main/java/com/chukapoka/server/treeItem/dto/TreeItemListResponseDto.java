package com.chukapoka.server.treeItem.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class TreeItemListResponseDto {
    private List<TreeItemDetailResponseDto> treeItem;
}
