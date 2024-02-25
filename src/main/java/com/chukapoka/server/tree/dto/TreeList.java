package com.chukapoka.server.tree.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class TreeList {

    /** 트리 리스트정보 */
    private Long treeId;
    private String title;
    private String type; // MINE or NOT_YEN_SEND
    private String linkId;
    private String sendId;
    private Long updatedBy;
    private LocalDateTime updatedAt;

    /** 트리색상 부분 추가 가능 */

}
