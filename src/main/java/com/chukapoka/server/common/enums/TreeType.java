package com.chukapoka.server.common.enums;

import lombok.Getter;

import java.util.HashMap;
import java.util.Map;

@Getter
public enum TreeType {
    MINE("내트리"),
    NOT_YET_SEND("미부여 트리");

    private final String description;
    private static final Map<String, TreeType> lookup = new HashMap<>();

    static {
        for (TreeType treeType : TreeType.values()) {
            lookup.put(treeType.getDescription(), treeType);
        }
    }

    TreeType(String description) {
        this.description = description;
    }

    public static TreeType getByDescription(String description) {
        return lookup.get(description);
    }

}
