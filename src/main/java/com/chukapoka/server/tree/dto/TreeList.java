package com.chukapoka.server.tree.dto;

import lombok.Data;
import java.time.LocalDateTime;

@Data
public class TreeList {

    /** 트리 리스트정보 */
    private String treeId;
    private String title;
    private String type; // MINE or NOT_YEN_SEND
    private String linkId;
    private String sendId;
    private Long updatedBy;
    private LocalDateTime updatedAt;
    /** 트리색상 부분 추가 가능 */
    private String treeBgColor;
    private String groundColor;
    private String treeTopColor;
    private String treeItemColor;
    private String treeBottomColor;

}
