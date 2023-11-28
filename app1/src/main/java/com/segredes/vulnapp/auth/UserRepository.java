package com.segredes.vulnapp.auth;

import com.segredes.vulnapp.controller.ApiController;
import com.segredes.vulnapp.model.User;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Repository;

@Repository
public class UserRepository {
    private static Logger logger = LoggerFactory.getLogger(UserRepository.class);

    public static User findUser(String username) throws UsernameNotFoundException {

        logger.info("findUser() - User: {}", username);

        // hardcoded, n precisamos de DB
        User userAdmin = new User("admin", "admin");
        userAdmin.setAdmin(true);

        User userRegular = new User("user", "1234");
        userRegular.setAdmin(false);

        User[] userDB = new User[] { userAdmin, userRegular };

        for (User u : userDB) {
            if (u.getUsername().equals(username)) {
                return u;
            }
        }

        return null;
    }

}