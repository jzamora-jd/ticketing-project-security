package com.cydeo.service.impl;

import com.cydeo.entity.User;
import com.cydeo.entity.common.UserPrincipal;
import com.cydeo.repository.UserRepository;
import com.cydeo.service.SecurityService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;


@Service
public class SecurityServiceImpl  implements SecurityService {


    private final UserRepository userRepository;//inject user to use find by username

    public SecurityServiceImpl(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException { // get it from DB and give it to UserDetails

        User user = userRepository.findByUserName(username);

        if(user==null){
            throw  new UsernameNotFoundException("This user does not exists");
        }

        return new UserPrincipal(user);//if it does find the user return - Spring User. We are using UserPrincipal mapper we created
    }
}
