package com.segredes.vulnapp.model;

import java.io.IOException;
import java.io.Serializable;
import com.google.gson.annotations.SerializedName;

public class User {

    @SerializedName("username")
    private String username;

    @SerializedName("password")
    private String password;

    @SerializedName("isAdmin")
    private boolean isAdmin = false;

    @SerializedName("picUrl")
    private String picUrl = null;

    public User(String username, String password) {
        this.username = username;
        this.password = password;
    }

    public User(String username, String password, boolean isAdmin) {
        this(username, password);
        this.isAdmin = isAdmin;
    }

    public String getUsername() {
        return username;
    }

    public String getPicUrl() {
        return picUrl;
    }

    public void setPicUrl(String picUrl) {
        this.picUrl = picUrl;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public boolean getAdmin() {
        return isAdmin;
    }

    public void setAdmin(boolean isAdmin) {
        this.isAdmin = isAdmin;
    }

}