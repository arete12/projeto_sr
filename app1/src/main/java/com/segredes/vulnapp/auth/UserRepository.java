package com.segredes.vulnapp.auth;

import com.segredes.vulnapp.controller.ApiController;
import com.segredes.vulnapp.model.User;

import java.util.HashSet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Repository;

import java.io.FileOutputStream;
import java.io.ObjectOutputStream;
import java.io.FileInputStream;
import java.io.ObjectInputStream;
import java.io.IOException;
import java.io.FileNotFoundException;

@Repository
public class UserRepository {
    private static Logger logger = LoggerFactory.getLogger(UserRepository.class);

    private static HashSet<User> userDB = null;

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

    public void storeState(String filename) throws FileNotFoundException, IOException {
        FileOutputStream fos = new FileOutputStream(filename);
        ObjectOutputStream oos = new ObjectOutputStream(fos);
        oos.writeObject(this.userDB);
        oos.flush();
        oos.close();
    }

    public void loadState(String filename) throws IOException, ClassNotFoundException {
        FileInputStream fis = new FileInputStream(filename);
        ObjectInputStream ois = new ObjectInputStream(fis);
        this.userDB = (HashSet<User>) ois.readObject();
        ois.close();
    }

}
