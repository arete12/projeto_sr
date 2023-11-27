package com.segredes.app1.app1.model;


public class User {
    private String username;
    private String password;
    private String isAdmin;

    public User(String username, String password) {
        this.username = username;
        this.password = password;
    }

    public String getUsername() {
        return username;
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

    public String getAdmin() {
        return isAdmin;
    }

    public void setAdmin(boolean isAdmin) {
        if(isAdmin){
            this.isAdmin = "true";
        }else{
            this.isAdmin = "false";
        }
        
    }


}