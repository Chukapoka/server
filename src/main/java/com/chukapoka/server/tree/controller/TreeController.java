package com.chukapoka.server.tree.controller;

import com.chukapoka.server.common.dto.BaseResponse;
import com.chukapoka.server.common.enums.ResultType;
import com.chukapoka.server.tree.dto.TreeDetailResponseDto;
import com.chukapoka.server.tree.dto.TreeListResponseDto;
import com.chukapoka.server.tree.dto.TreeCreateRequestDto;
import com.chukapoka.server.tree.dto.TreeModifyRequestDto;
import com.chukapoka.server.tree.entity.Tree;
import com.chukapoka.server.tree.service.TreeService;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;



@RestController
@AllArgsConstructor
@RequestMapping("/api/tree")
public class TreeController {

    @Autowired
    private final TreeService treeService ;

    /**트리 생성 */
    @PostMapping
    public BaseResponse<Tree>createTree(@Valid @RequestBody TreeCreateRequestDto treeRequestDto) {
        Tree responseDto = treeService.createTree(treeRequestDto);
        return new BaseResponse<>(ResultType.SUCCESS, responseDto);
    }

    /** 트리리스트 목록 */
    @GetMapping
    public BaseResponse<TreeListResponseDto> treeList() {
        TreeListResponseDto responseDto = treeService.treeList();
        return new BaseResponse<>(ResultType.SUCCESS, responseDto);
    }

    /** 트리상세 정보 */
    @GetMapping("/{treeId}")
    private BaseResponse<TreeDetailResponseDto> treeDetail(@PathVariable("treeId") Long treeId) {
        TreeDetailResponseDto responseDto = treeService.treeDetail(treeId);
        return new BaseResponse<>(ResultType.SUCCESS, responseDto);
    }

    /** 트리 수정 */
    @PutMapping("/{treeId}")
    public BaseResponse<Tree> treeModify(@PathVariable("treeId") Long treeId,
                                         @RequestBody TreeModifyRequestDto treeModifyDto) {
        Tree responseDto = treeService.treeModify(treeId, treeModifyDto);
        return new BaseResponse<>(ResultType.SUCCESS, responseDto);
    }


    /** 트리 삭제 */
    @DeleteMapping("/{treeId}")
    public BaseResponse<Void> treeDelete(@PathVariable("treeId") Long treeId) {
        treeService.treeDelete(treeId);
        return new BaseResponse<>(ResultType.SUCCESS, null);
    }

}

