package com.cydeo.service;

import org.springframework.security.core.userdetails.UserDetailsService;

public interface SecurityService extends UserDetailsService { //we need to create a layer, UserDetailsService has loadByUserName method
}
