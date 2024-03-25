package com.chukapoka.server.treeItem.repository;

import com.chukapoka.server.treeItem.entity.TreeItem;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface TreeItemRepository extends JpaRepository<TreeItem, String> {
    List<TreeItem> findByTreeId(String treeId);
    Optional<TreeItem> findByIdAndUpdatedBy(String treeItemId, long userId);
}
