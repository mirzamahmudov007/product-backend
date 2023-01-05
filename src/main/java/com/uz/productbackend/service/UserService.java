package com.uz.productbackend.service;

import com.uz.productbackend.entity.User;
import com.uz.productbackend.system.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UserService {

    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    public UserService(PasswordEncoder passwordEncoder, UserRepository userRepository) {
        this.passwordEncoder = passwordEncoder;
        this.userRepository = userRepository;
    }

    public User saveUser(User user) {
        user.setPassword(passwordEncoder.encode(user.getPassword()));
      return userRepository.save(user);
    }

    public boolean checkPassword(String password) {
        return password.length() > 4; // true => yaroqli
    }

    public boolean existByUsername(String username) {
        return userRepository.existsByUsername(username); // true =>  yaroqsiz
    }

}
