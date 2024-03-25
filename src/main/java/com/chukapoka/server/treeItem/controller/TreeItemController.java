package com.chukapoka.server.treeItem.controller;

import com.chukapoka.server.common.dto.BaseResponse;
import com.chukapoka.server.common.dto.CustomUserDetails;
import com.chukapoka.server.common.enums.ResultType;
import com.chukapoka.server.treeItem.dto.TreeItemCreateRequestDto;
import com.chukapoka.server.treeItem.dto.TreeItemDetailResponseDto;
import com.chukapoka.server.treeItem.dto.TreeItemListResponseDto;
import com.chukapoka.server.treeItem.dto.TreeItemModifyRequestDto;
import com.chukapoka.server.treeItem.service.TreeItemService;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

@RestController
@AllArgsConstructor
@RequestMapping("api/treeItem")
public class TreeItemController {

    private final TreeItemService treeItemService;
    /** 트리아이템 생성 */
    @PostMapping
    public BaseResponse<TreeItemDetailResponseDto> createTreeItem(@Valid @RequestBody TreeItemCreateRequestDto treeItemCreateRequestDto) {
        long userId = ((CustomUserDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal()).getUserId();
        TreeItemDetailResponseDto responseDto = treeItemService.createTreeItem(treeItemCreateRequestDto, userId);
        return new BaseResponse<>(ResultType.SUCCESS, responseDto);
    }

    /** 트리리스트 목록 */
    @GetMapping
    public BaseResponse<TreeItemListResponseDto> treeItemList() {
        long userId = ((CustomUserDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal()).getUserId();
        TreeItemListResponseDto responseDto = treeItemService.treeList(userId);
        return new BaseResponse<>(ResultType.SUCCESS, responseDto);
    }

    /** 트리상세 정보 */
    @GetMapping("/{treeItemId}")
    private BaseResponse<TreeItemDetailResponseDto> treeItemDetail(@PathVariable("treeItemId") String treeItemId) {
        long userId = ((CustomUserDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal()).getUserId();
        TreeItemDetailResponseDto responseDto = treeItemService.treeDetail(treeItemId, userId);
        return new BaseResponse<>(ResultType.SUCCESS, responseDto);
    }

    /** 트리 수정 */
    @PutMapping("/{treeItemId}")
    public BaseResponse<TreeItemDetailResponseDto> treeItemModify(@PathVariable("treeItemId") String treeItemId,
                                                          @Valid @RequestBody TreeItemModifyRequestDto treeItemModifyDto) {
        long userId = ((CustomUserDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal()).getUserId();
        TreeItemDetailResponseDto responseDto = treeItemService.treeModify(treeItemId, treeItemModifyDto, userId);
        return new BaseResponse<>(ResultType.SUCCESS, responseDto);
    }


    /** 트리 삭제 */
    @DeleteMapping("/{treeItemId}")
    public BaseResponse<Void> treeItemDelete(@PathVariable("treeItemId") String treeItemId) {
        long userId = ((CustomUserDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal()).getUserId();
        treeItemService.treeItemDelete(treeItemId, userId);
        return new BaseResponse<>(ResultType.SUCCESS, null);
    }
}
