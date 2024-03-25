package com.chukapoka.server.tree.service;

import com.chukapoka.server.tree.dto.TreeDetailResponseDto;
import com.chukapoka.server.tree.dto.TreeListResponseDto;
import com.chukapoka.server.tree.dto.TreeCreateRequestDto;
import com.chukapoka.server.tree.dto.TreeModifyRequestDto;

public interface TreeService {

    /** 트리 저장 */
    TreeDetailResponseDto createTree(TreeCreateRequestDto treeRequestDto, long userId);

    /** 트리리스트 조회(리스트용 모델) */
    TreeListResponseDto treeList(long userId);

    /** 트리 상세 정보 조회 (상세정보 모델) */
    TreeDetailResponseDto treeDetail(String treeId, long userId);

    /** 트리 수정 */
    TreeDetailResponseDto treeModify(String treeId,long userId, TreeModifyRequestDto treeModifyDto);

    /** 트리 삭제 */
    void treeDelete(String treeId,long userId);

}
