package com.chukapoka.server.tree.entity;

import jakarta.persistence.*;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.DynamicUpdate;
import org.springframework.data.annotation.LastModifiedDate;

import java.time.LocalDateTime;
import java.util.concurrent.atomic.AtomicInteger;

@Entity
@Data
@AllArgsConstructor
@NoArgsConstructor
@DynamicUpdate // 데이터의 변경사항이 있는 것만 수정
@Builder
@Table(name = "tb_tree")
public class Tree {
    @Id
    @Column(name = "treeId", unique = true, nullable = false)
    private String treeId;

    /** 트리제목 */
    @Column(name = "title")
    private String title;

    /** 내트리 || 미부여 트리 */
    @Column(name = "type")
    private String type;

    /** 트리 링크를 특정하기 위한 id*/
    @Column(name = "linkId", nullable = false, unique = true, length = 200)
    private String linkId;

    /** 타인에게 트리를 전달할 때 트리를 특정하기 위한 id */
    @Column(name = "sendId", unique = true, length = 200)
    private String sendId;

    /** 트라 관련 색상은 String -> enum type으로 상수로 바꿔야 관리가 더 편할것같음 */
    @Column(name = "treeBgColor", nullable = true)
    private String treeBgColor;

    @Column(name = "groundColor", nullable = true)
    private String groundColor;

    @Column(name = "treeTopColor", nullable = true)
    private String treeTopColor;

    @Column(name = "treeItemColor", nullable = true)
    private String treeItemColor;

    @Column(name = "treeBottomColor", nullable = true)
    private String treeBottomColor;

    /** userId가 값임 */
    @Column(name = "updatedBy")
    private Long updatedBy;

    /** 생성 시간 */
    @Column(name = "updatedAt", nullable = false)
    @LastModifiedDate
    private LocalDateTime updatedAt;

    @PrePersist
    public void prePersist() {
        this.updatedAt = LocalDateTime.now();
        if(this.treeId == null) {
            this.treeId = TreeId();
        }

    }

    private static final AtomicInteger counter = new AtomicInteger(0);
    private static String TreeId() {
        return "treeId" + counter.incrementAndGet();
    }

}
