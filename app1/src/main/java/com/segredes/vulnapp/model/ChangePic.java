package com.segredes.vulnapp.model;

public class ChangePic {
    private String newUrl;

    public ChangePic(String username, String newurl) {
        this.newUrl = newurl;
    }

    public String getNewUrl() {
        return newUrl;
    }

    public void setNewUrl(String newurl) {
        this.newUrl = newurl;
    }
}
