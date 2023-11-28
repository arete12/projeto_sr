package com.segredes.vulnapp.auth;

import com.segredes.vulnapp.controller.ApiController;
import com.segredes.vulnapp.model.User;

import java.util.HashSet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Repository;

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

}