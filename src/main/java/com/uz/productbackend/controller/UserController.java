package com.uz.productbackend.controller;

import com.uz.productbackend.entity.User;
import com.uz.productbackend.service.UserService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/register")
    public ResponseEntity<String> save(@RequestBody User user) {
        if (!userService.checkPassword(user.getPassword())) {
            return new ResponseEntity<>("parol yaroqsiz", HttpStatus.BAD_REQUEST);
        }
        if (userService.existByUsername(user.getUsername())) {
            return new ResponseEntity<>("bu user band!", HttpStatus.BAD_REQUEST);
        }
        userService.saveUser(user);
        return ResponseEntity.ok("success");
    }


}
