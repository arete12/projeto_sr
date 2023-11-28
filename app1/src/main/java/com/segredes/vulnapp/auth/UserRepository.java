package com.segredes.vulnapp.auth;

import com.segredes.vulnapp.model.User;
import org.springframework.stereotype.Repository;

@Repository
public class UserRepository {

    public static User findUser(String username) {

        // hardcoded, n precisamos de DB
        User userAdmin = new User("admin", "admin");
        userAdmin.setAdmin(true);

        User userRegular = new User("user", "1234");
        userRegular.setAdmin(false);

        User[] userDB = new User[] { userAdmin, userRegular };

        for (User u : userDB) {
            if (u.getUsername().equals(username)) {
                System.out.println(
                        "UserRepository.findUser() - Found user " + u.getUsername() + ", isAdmin = " + u.getAdmin());
                return u;
            }
        }

        return null;
    }
}