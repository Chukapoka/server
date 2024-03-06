package com.chukapoka.server.tree.repository;



import com.chukapoka.server.tree.dto.TreeList;
import com.chukapoka.server.tree.entity.Tree;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface TreeRepository extends JpaRepository<Tree, String> {
    Optional<Tree> findById(String treeId);

    /** treeList 조회 어떤 방법으로 할지 1. jpa @Query로 직접 찾기 2. jpa로 모두 찾은후 modelmapper로 맵핑할지
     * @Query("SELECT new com.chukapoka.server.tree.dto.TreeList(tree.treeId, tree.title, tree.type, tree.linkId, tree.sendId, tree.updatedBy, tree.updatedAt) FROM Tree tree")
     * List<TreeList> findAllTrees();
     */



}
