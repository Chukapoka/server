package com.chukapoka.server.domain;

public class ResponseData {

    public int id;
    public boolean isSuccess;

    public ResponseData(int id, boolean isSuccess) {
        this.id = id;
        this.isSuccess = isSuccess;
    }

}
