package com.chukapoka.server.tree.dto;

import com.chukapoka.server.tree.entity.Tree;
import com.chukapoka.server.treeItem.entity.TreeItem;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class TreeDetailResponseDto {

    /** 트리상세 정보 */
    private String treeId;
    private String title;
    private String type; // MINE or NOT_YEN_SEND
    private String linkId;
    private String sendId;
    private String treeBgColor;
    private String groundColor;
    private String treeTopColor;
    private String treeItemColor;
    private String treeBottomColor;
    private Long updatedBy;
    private LocalDateTime updatedAt;

    /** treeItem 목록 */
    private List<TreeItem> treeItem;


    /** 트리 생성, 수정 constructor */
    public TreeDetailResponseDto(Tree tree) {
        this.treeId = tree.getTreeId();
        this.title = tree.getTitle();
        this.type = tree.getType();
        this.linkId = tree.getLinkId();
        this.sendId = tree.getSendId();
        this.treeBgColor = tree.getTreeBgColor();
        this.groundColor = tree.getGroundColor();
        this.treeTopColor = tree.getTreeTopColor();
        this.treeItemColor = tree.getTreeItemColor();
        this.treeBottomColor = tree.getTreeBottomColor();
        this.updatedBy = tree.getUpdatedBy();
        this.updatedAt = tree.getUpdatedAt();
    }

    /** 트리 상세정보 constructor */
    public TreeDetailResponseDto(Tree tree,  List<TreeItem> treeItem) {
        this.treeId = tree.getTreeId();
        this.title = tree.getTitle();
        this.type = tree.getType();
        this.linkId = tree.getLinkId();
        this.sendId = tree.getSendId();
        this.treeBgColor = tree.getTreeBgColor();
        this.groundColor = tree.getGroundColor();
        this.treeTopColor = tree.getTreeTopColor();
        this.treeItemColor = tree.getTreeItemColor();
        this.treeBottomColor = tree.getTreeBottomColor();
        this.updatedBy = tree.getUpdatedBy();
        this.updatedAt = tree.getUpdatedAt();
        this.treeItem = treeItem;
    }
}
