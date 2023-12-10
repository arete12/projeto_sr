package com.segredes.vulnapp.model;

import org.apache.commons.validator.routines.UrlValidator;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

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
        String[] schemes = { "http", "https" };
        UrlValidator urlValidator = new UrlValidator(schemes);

        return urlValidator.isValid(url);
    }

    public boolean isValidImage(InputStream contentStream) throws IOException {
        byte[] magicBytes = new byte[4]; // Adjust the number of bytes as needed

        // Read the first few bytes of the stream
        int bytesRead = contentStream.read(magicBytes);

        // Compare the read bytes with known magic byte patterns for image formats
        return bytesRead >= 4 && (Arrays.equals(magicBytes,
                // JPG/JPEG    
                new byte[] { (byte) 0xFF, (byte) 0xD8, (byte) 0xFF, (byte) 0xDB })
                || Arrays.equals(magicBytes, new byte[] { (byte) 0xFF, (byte) 0xD8, (byte) 0xFF, (byte) 0xE0 })
                || Arrays.equals(magicBytes, new byte[] { (byte) 0xFF, (byte) 0xD8, (byte) 0xFF, (byte) 0xEE })
                || Arrays.equals(magicBytes, new byte[] { (byte) 0xFF, (byte) 0xD8, (byte) 0xFF, (byte) 0xE1 })
                // PNG
                || Arrays.equals(magicBytes, new byte[] { (byte) 0x89, (byte) 0x50, (byte) 0x4E, (byte) 0x47 }));

    }

}
