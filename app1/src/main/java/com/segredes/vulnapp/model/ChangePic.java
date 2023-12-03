package com.segredes.vulnapp.model;
import org.apache.commons.validator.routines.UrlValidator;

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

    public boolean isValidUrl(String url) {
        String[] schemes = {"http", "https"};
        UrlValidator urlValidator = new UrlValidator(schemes);

        return urlValidator.isValid(url);
    }
}
