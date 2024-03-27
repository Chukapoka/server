package com.chukapoka.server.tree.dto;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class TreeListResponseDto {

    /** 트리 리스트 목록 */
    private List<TreeList> treeList;
}


