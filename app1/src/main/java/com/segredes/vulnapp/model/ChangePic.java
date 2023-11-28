package com.segredes.vulnapp.model;

public class ChangePic {
    private String username;
    private String newurl;

    public ChangePic(String username, String newurl) {
        this.username = username;
        this.newurl = newurl;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getNewurl() {
        return newurl;
    }

    public void setNewurl(String newurl) {
        this.newurl = newurl;
    }
}
