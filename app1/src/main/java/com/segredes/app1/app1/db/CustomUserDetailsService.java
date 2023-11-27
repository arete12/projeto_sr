package com.segredes.app1.app1.db;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.segredes.app1.app1.model.User;

import java.util.ArrayList;
import java.util.List;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    public CustomUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        System.out.println("CustomUserDetailsService.loadUserByUsername()");

        User user = userRepository.findUser(username);
        if(user == null){
            System.out.println("CustomUserDetailsService.loadUserByUsername() - User not found");
            throw new UsernameNotFoundException("CustomUserDetailsService.loadUserByUsername() - User not found");
        }

        //List<String> roles = new ArrayList<>();
        //roles.add("USER");
        
        UserDetails userDetails = org.springframework.security.core.userdetails.User.builder()
                .username(user.getUsername())
                .password(user.getPassword())
                //.roles(roles.toArray(new String[0]))
                .build();
        System.out.println("CustomUserDetailsService.loadUserByUsername() - User found!");
        return userDetails;
    }
}