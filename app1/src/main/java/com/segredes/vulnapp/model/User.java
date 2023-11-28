package com.segredes.vulnapp.model;

import java.io.IOException;
import java.io.Serializable;

public class User implements Serializable {
    private String username;
    private String password;
    private boolean isAdmin = false;
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

    private void readObject(java.io.ObjectInputStream stream)
            throws IOException, ClassNotFoundException {
        User user = (User) stream.readObject();
        user.getUsername();
    }

}