package com.segredes.vulnapp.model;
import org.apache.commons.validator.routines.DomainValidator;
import org.apache.commons.validator.routines.InetAddressValidator;

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
        InetAddressValidator addressValidator = InetAddressValidator.getInstance();
        DomainValidator domainValidator = DomainValidator.getInstance();

        if (addressValidator.isValid(url) || domainValidator.isValid(url)) {
            return true;
        }
        
        return false;
    }
}
