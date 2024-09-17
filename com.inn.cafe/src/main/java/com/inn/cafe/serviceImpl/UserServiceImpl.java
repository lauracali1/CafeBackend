package com.inn.cafe.serviceImpl;

import com.google.common.base.Strings;
import com.inn.cafe.JWT.CustomerUsersDetailsService;
import com.inn.cafe.JWT.JwtFilter;
import com.inn.cafe.JWT.JwtUtil;
import com.inn.cafe.JWT.CustomerUsersDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import com.inn.cafe.JWT.JwtUtil;
import com.inn.cafe.POJO.User;
import com.inn.cafe.constents.CafeConstants;
import com.inn.cafe.dao.UserDao;
import com.inn.cafe.service.UserService;
import com.inn.cafe.utils.CafeUtils;
import com.inn.cafe.utils.EmailUtils;
import com.inn.cafe.wrapper.UserWrapper;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import java.util.*;

@Slf4j
@Service
public class UserServiceImpl implements UserService {


    private static final Logger log = LoggerFactory.getLogger(UserServiceImpl.class);

    @Autowired
    UserDao userDao;

    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    CustomerUsersDetailsService customerUsersDetailsService;

    @Autowired
    JwtUtil jwtUtil;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Autowired
    JwtFilter jwtFilter;

    @Autowired
    EmailUtils emailUtils;



    @Override
    public ResponseEntity<String> signUp(Map<String, String> requestMap) {
        log.info("Inside signup {}", requestMap);
        try {
        if (validateSignUpMap(requestMap)) {
            User user = userDao.findByEmailId(requestMap.get("email"));
            if (Objects.isNull(user)) {
                userDao.save(getUserFromMap(requestMap));
                return CafeUtils.getResponseEntity("Successfully Registered .", HttpStatus.OK);
            } else {
                return CafeUtils.getResponseEntity("Email already exists.", HttpStatus.BAD_REQUEST);
            }
        } else {
            return CafeUtils.getResponseEntity(CafeConstants.INVALID_DATA, HttpStatus.BAD_REQUEST);
        }


        } catch (Exception ex) {
           ex.printStackTrace();
        }
        return CafeUtils.getResponseEntity(CafeConstants.SOMETHING_WENT_WRONG, HttpStatus.INTERNAL_SERVER_ERROR);
    }

    @Override
    public ResponseEntity<String> login(Map<String, String> requestMap) {
        log.info("Inside login for user: {}", requestMap.get("email"));
        try {
            Authentication auth = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(requestMap.get("email"), requestMap.get("password"))
            );
            if (auth.isAuthenticated()) {
                if (customerUsersDetailsService.getUserDetail().getStatus().equalsIgnoreCase("true")) {
                    String token = jwtUtil.generateToken(customerUsersDetailsService.getUserDetail().getEmail(),
                            customerUsersDetailsService.getUserDetail().getRole());
                    return new ResponseEntity<>("{\"token\":\"" + token + "\"}", HttpStatus.OK);
                } else {
                    log.warn("User {} is not approved by admin", requestMap.get("email"));
                    return new ResponseEntity<>("{\"message\":\"Wait for admin approval.\"}", HttpStatus.FORBIDDEN);
                }
            }
        } catch (BadCredentialsException e) {
            log.error("Bad credentials for user: {}", requestMap.get("email"));
            return new ResponseEntity<>("{\"message\":\"Invalid username or password.\"}", HttpStatus.UNAUTHORIZED);
        } catch (Exception ex) {
            log.error("Login error for user: {}", requestMap.get("email"), ex);
            return new ResponseEntity<>("{\"message\":\"An error occurred during login.\"}", HttpStatus.INTERNAL_SERVER_ERROR);
        }
        return new ResponseEntity<>("{\"message\":\"Invalid login attempt.\"}", HttpStatus.BAD_REQUEST);
    }

    @Override
    public ResponseEntity<List<UserWrapper>> getAllUser() {
        try{
            if(jwtFilter.isAdmin()){
                return new ResponseEntity<>(userDao.getAllUser(),HttpStatus.OK);
            }else{
                return new ResponseEntity<>(new ArrayList<>(),HttpStatus.UNAUTHORIZED);
            }
        }catch(Exception ex){
            ex.printStackTrace();
        }
        return  new ResponseEntity<> (new ArrayList<>(),HttpStatus.INTERNAL_SERVER_ERROR);
    }


    @Override
    public ResponseEntity<String> update(Map<String, String> requestMap) {
        try{
            if(jwtFilter.isAdmin()){
                int userId = Integer.parseInt(requestMap.get("id"));
                Optional<User> optional = userDao.findById(userId);
                // Optional<User> optional = UserDao.findById(Integer.parseInt(requestMap.get("id")));
                if(!optional.isEmpty()){
                    userDao.updateStatus(requestMap.get("status"), Integer.parseInt(requestMap.get("id")));
                    sendMailToAllAdmin(requestMap.get("status"), optional.get().getEmail(), userDao.getAllAdmin());
                    return CafeUtils.getResponseEntity("User Status  Updated Successfully.",HttpStatus.OK);
                }else{
                    return CafeUtils.getResponseEntity("User doesn't exists.",HttpStatus.OK);
                }

            }else{
                return CafeUtils.getResponseEntity(CafeConstants.UNAUTHORIZED_ACCESS,HttpStatus.UNAUTHORIZED);
            }

        }catch (Exception ex){
            ex.printStackTrace();
        }
        return CafeUtils.getResponseEntity(CafeConstants.SOMETHING_WENT_WRONG,HttpStatus.INTERNAL_SERVER_ERROR);
    }

    private boolean validateSignUpMap(Map<String, String> requestMap) {
        if(requestMap.containsKey("name") && requestMap.containsKey("contactNumber")
                && requestMap.containsKey("email") && requestMap.containsKey("password")){
            return true;
        }
            return false;
        }

    private User getUserFromMap(Map<String, String> requestMap) {
        User user = new User();
        user.setName(requestMap.get("name"));
        user.setContactNumber(requestMap.get("contactNumber"));
        user.setEmail(requestMap.get("email"));
        user.setPassword(passwordEncoder.encode(requestMap.get("password")));
        user.setStatus("false");
        user.setRole("user");
        return user;
    }

    private void sendMailToAllAdmin(String status, String user, List<String> allAdmin) {
        allAdmin.remove(jwtFilter.getCurrentUser());
        if (status != null && status.equalsIgnoreCase("true")){
            emailUtils.sendSimpleMessage(jwtFilter.getCurrentUser(), "Account Approved","User:- " +user +"\nis approved by \nADMIN" + jwtFilter.getCurrentUser(), allAdmin);
        }else{
            emailUtils.sendSimpleMessage(jwtFilter.getCurrentUser(), "Account Disabled","User:- " +user +"\nis disabled by \nADMIN" + jwtFilter.getCurrentUser(), allAdmin);
        }
    }

    @Override
    public ResponseEntity<String> checkToken() {
       return CafeUtils.getResponseEntity("true",HttpStatus.OK);
    }


    @Override
    public ResponseEntity<String> changePassword(Map<String, String> requestMap) {
        try {
            String currentUser = jwtFilter.getCurrentUser();
            log.info("Changing password for user: {}", currentUser);

            if (currentUser == null || currentUser.isEmpty()) {
                return CafeUtils.getResponseEntity("User not authenticated", HttpStatus.UNAUTHORIZED);
            }

            User userObj = userDao.findByEmail(currentUser);
            if (userObj == null) {
                log.warn("User not found: {}", currentUser);
                return CafeUtils.getResponseEntity("User not found", HttpStatus.NOT_FOUND);
            }

            String oldPassword = requestMap.get("oldPassword");
            String newPassword = requestMap.get("newPassword");

            if (oldPassword == null || newPassword == null || oldPassword.isEmpty() || newPassword.isEmpty()) {
                log.warn("Old or new password is missing for user: {}", currentUser);
                return CafeUtils.getResponseEntity("Old or new password is missing", HttpStatus.BAD_REQUEST);
            }

            if (passwordEncoder.matches(oldPassword, userObj.getPassword())) {
                userObj.setPassword(passwordEncoder.encode(newPassword));
                userDao.save(userObj);
                log.info("Password updated successfully for user: {}", currentUser);
                return CafeUtils.getResponseEntity("Password updated successfully", HttpStatus.OK);
            } else {
                log.warn("Incorrect old password for user: {}", currentUser);
                return CafeUtils.getResponseEntity("Incorrect old password", HttpStatus.BAD_REQUEST);
            }
        } catch (Exception ex) {
            log.error("Error changing password: ", ex);
            return CafeUtils.getResponseEntity(CafeConstants.SOMETHING_WENT_WRONG, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @Override
    public ResponseEntity<String> forgotPassword(Map<String, String> requestMap) {
        try {
            User user = userDao.findByEmail(requestMap.get("email"));
            if(!Objects.isNull(user) && !Strings.isNullOrEmpty(user.getEmail()))
                emailUtils.forgotMail(user.getEmail(),"Credintials by Cafe Management System.", user.getPassword());
                return CafeUtils.getResponseEntity("Check your email for credintials.",HttpStatus.OK);
        }catch (Exception ex){
            ex.printStackTrace();
        }
        return CafeUtils.getResponseEntity("Incorrect email",HttpStatus.INTERNAL_SERVER_ERROR);
    }
}


