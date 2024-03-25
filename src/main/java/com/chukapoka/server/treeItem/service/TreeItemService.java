package com.chukapoka.server.treeItem.service;
import com.chukapoka.server.treeItem.dto.TreeItemCreateRequestDto;
import com.chukapoka.server.treeItem.dto.TreeItemDetailResponseDto;
import com.chukapoka.server.treeItem.dto.TreeItemListResponseDto;
import com.chukapoka.server.treeItem.dto.TreeItemModifyRequestDto;

public interface TreeItemService {

    /** 트리 아이템 생성 */
    TreeItemDetailResponseDto createTreeItem(TreeItemCreateRequestDto treeItemCreateRequestDto, long userId);

    /** 트리아이템리스트 조회(리스트용 모델) */
    TreeItemListResponseDto treeList(long userId);

    /** 트리아이템 상세 정보 조회 (상세정보 모델) */
    TreeItemDetailResponseDto treeDetail(String treeItemId, long userId);

    /** 트리아이템 수정 */
    TreeItemDetailResponseDto treeModify(String treeItemId, TreeItemModifyRequestDto treeItemModifyDto, long userId);

    /** 트리아이템 삭제 */
    void treeItemDelete(String treeItemId, long userId);
}
