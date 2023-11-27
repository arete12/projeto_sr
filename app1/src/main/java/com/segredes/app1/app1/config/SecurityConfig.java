package com.segredes.app1.app1.config;

import java.util.ArrayList;
import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
//import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.segredes.app1.app1.auth.JWTAuthFilter;
import com.segredes.app1.app1.db.CustomUserDetailsService;
import com.segredes.app1.app1.db.UserRepository;
import com.segredes.app1.app1.model.User;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

        private final CustomUserDetailsService userDetailsService;
        private final JWTAuthFilter jwtAuthFilter;

        public SecurityConfig(CustomUserDetailsService customUserDetailsService, JWTAuthFilter jwtAuthFilter) {
                this.userDetailsService = customUserDetailsService;
                this.jwtAuthFilter = jwtAuthFilter;
        }

        @Bean
        public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
                http
                                .authorizeHttpRequests((requests) -> requests
                                                .requestMatchers("/", "/index", "/api/**", "/favicon.ico").permitAll()
                                                .anyRequest().authenticated())
                                .formLogin((form) -> form
                                                .loginPage("/login")
                                                .permitAll())
                                .logout((logout) -> logout.permitAll())
                                .csrf((csrf) -> csrf.disable())
                                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

                return http.build();

        }

        @Bean
        public AuthenticationManager authenticationManager(HttpSecurity http, NoOpPasswordEncoder noOpPasswordEncoder)
                        throws Exception {
                AuthenticationManagerBuilder authenticationManagerBuilder = http
                                .getSharedObject(AuthenticationManagerBuilder.class);
                authenticationManagerBuilder.userDetailsService(userDetailsService)
                                .passwordEncoder(noOpPasswordEncoder);
                return authenticationManagerBuilder.build();
        }

        @SuppressWarnings("deprecation")
        @Bean
        public NoOpPasswordEncoder passwordEncoder() {
                return (NoOpPasswordEncoder) NoOpPasswordEncoder.getInstance();
        }

        /*
         * @Bean
         * public UserDetailsService userDetailsService() {
         * UserDetails user = User.withDefaultPasswordEncoder()
         * .username("admin")
         * .password("admin")
         * .roles("USER")
         * .build();
         * 
         * return new InMemoryUserDetailsManager(user);
         * }
         * 
         */

}