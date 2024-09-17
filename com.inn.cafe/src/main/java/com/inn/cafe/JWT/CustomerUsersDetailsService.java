package com.inn.cafe.JWT;

import com.inn.cafe.dao.UserDao;
import com.inn.cafe.serviceImpl.UserServiceImpl;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Objects;

@Slf4j
@Service
public class CustomerUsersDetailsService implements UserDetailsService {

    private static final Logger log = LoggerFactory.getLogger(CustomerUsersDetailsService.class);

    @Autowired
    private UserDao userDao;
    private com.inn.cafe.POJO.User userDetail;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        log.info("Inside loadUserByUsername: {}", username);
        userDetail = userDao.findByEmailId(username);
        if (Objects.isNull(userDetail)) {
            log.warn("User not found: {}", username);
            throw new UsernameNotFoundException("User not found: " + username);
        } else {
            log.info("User found: {}", userDetail.getEmail());
            return new User(userDetail.getEmail(), userDetail.getPassword(), new ArrayList<>());
        }
    }

    public com.inn.cafe.POJO.User getUserDetail() {
        return userDetail;
    }
}
