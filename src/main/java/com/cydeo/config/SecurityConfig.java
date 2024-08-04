package com.cydeo.config;

import com.cydeo.service.SecurityService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Configuration
public class SecurityConfig {

    private final SecurityService securityService;
    private final AuthSuccessHandler authSuccessHandler;

    public SecurityConfig(SecurityService securityService, AuthSuccessHandler authSuccessHandler) {
        this.securityService = securityService;
        this.authSuccessHandler = authSuccessHandler;
    }

//    @Bean
//    public UserDetailsService userDetailsService(PasswordEncoder encoder){
//
//
//        List<UserDetails> userList =  new ArrayList<>();
//
//        userList.add(
//                new User("mike", encoder.encode("password"), Arrays.asList(new SimpleGrantedAuthority("ROLE_ADMIN"))));
//        userList.add(
//                new User("ozzy", encoder.encode("password"), Arrays.asList(new SimpleGrantedAuthority("ROLE_MANAGER"))));
//
//
//        return new InMemoryUserDetailsManager(userList);
//    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception { //used to restrict pages based on role
        return http
                .authorizeRequests()//dont want login page to be authorized, all users should be able to see Login
//                .antMatchers("/user/**").hasRole("Admin") // hasRole is putting ROLE_ prefix
                .antMatchers("/user/**").hasAuthority("Admin")//give access to all pages in User page
                .antMatchers("/project/**").hasAuthority("Manager")
                .antMatchers("/task/employee/**").hasAuthority("Employee")//hasAuthority not putting any prefix
                .antMatchers("/task/**").hasAuthority("Manager")
//                .antMatchers("/task/**").hasAnyRole("EMPLOYEE","ADMIN") //more than one role can access
//                .antMatchers("task/**").hasAuthority("ROLE_EMPLOYEE")

                .antMatchers( //let all access login using permitAll()
                       "/",
                       "/login",
                       "/fragments/**",
                       "/assets/**",
                       "/images/**"
                ).permitAll() //all users should have access to login page
                .anyRequest().authenticated()
                .and()
//                .httpBasic()
                .formLogin()//tell spring you want to use the login page
                    .loginPage("/login")
//                    .defaultSuccessUrl("/welcome")
                    .successHandler(authSuccessHandler) //where you want to land - welcome page
                    .failureUrl("/login?error=true") // if anything goes wrong
                    .permitAll() //everyone should have access to this page
                .and()//connector
                .logout()//
                    .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))//looking for thymleaf page to log out
                    .logoutSuccessUrl("/login")
                .and()
                .rememberMe()
                    .tokenValiditySeconds(120)
                    .key("cydeo")
                    .userDetailsService(securityService)
                .and()
                .build();//needed at the end

    }



















}
