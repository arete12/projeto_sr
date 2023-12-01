package com.segredes.vulnapp.auth;

import com.segredes.vulnapp.controller.ApiController;
import com.segredes.vulnapp.model.User;

import java.util.Base64;
import java.util.HashSet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Repository;

import java.io.FileOutputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.ObjectInputStream;
import java.io.IOException;
import java.io.FileNotFoundException;

@Repository
public class UserRepository {
    private static Logger logger = LoggerFactory.getLogger(UserRepository.class);

    private static HashSet<User> userDB = null;

    public static void setUserDB(HashSet<User> userDB) {
        UserRepository.userDB = userDB;
    }

    public static HashSet<User> getUserDB() {
        return userDB;
    }

    public static User findUser(String username) throws UsernameNotFoundException {

        logger.info("findUser() - User: {}", username);

        if (userDB == null) {
            logger.info("findUser() - userDB is null");

            userDB = new HashSet<>();
            userDB.add(new User("user", "1234"));
            userDB.add(new User("admin", "admin", true));
        }

        for (User u : userDB) {
            if (u.getUsername().equals(username)) {
                logger.info("findUser() - Found User: {}", username);

                return u;
            }
        }

        logger.info("findUser() - Not Found User: {}", username);

        return null;
    }

    public String storeState() throws FileNotFoundException, IOException {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(UserRepository.userDB);
        oos.close();
        return Base64.getEncoder().encodeToString(baos.toByteArray());
    }

    // public void loadState(String filename) throws IOException,
    // ClassNotFoundException {
    // FileInputStream fis = new FileInputStream(filename);
    // ObjectInputStream ois = new ObjectInputStream(fis);
    // // this.userDB = (HashSet<User>) ois.readObject();
    // ois.close();
    // }

    public void loadState(String filestring) throws IOException, ClassNotFoundException {
        byte[] data = Base64.getDecoder().decode(filestring);
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
        HashSet<User> o = (HashSet<User>) ois.readObject();
        UserRepository.setUserDB(o);
        ois.close();
    }

}
