package com.jwt.authentication.service;

import com.jwt.authentication.dto.RegisterRequest;
import com.jwt.authentication.model.RoleModel;
import com.jwt.authentication.model.UserModel;
import com.jwt.authentication.repository.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

@Service
public class UserService implements UserDetailsService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    public UserService(UserRepository userRepository, BCryptPasswordEncoder bCryptPasswordEncoder) {
        this.userRepository = userRepository;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userRepository.findUserModelByUsername(username).orElseThrow(
                () -> new UsernameNotFoundException("user not found with username is: " + username)
        );
    }

    public String register(RegisterRequest request) {
        boolean isTaken = userRepository.findUserModelByUsername(request.username()).isPresent();

        if (isTaken){
            throw new IllegalStateException("username is already taken");
        }
        UserModel user = new UserModel(
                request.username(),
                bCryptPasswordEncoder.encode(request.password()),
                request.firstName(),
                request.lastName(),
                RoleModel.USER
        );
        try {
            userRepository.save(user);
        } catch (Exception e) {
            throw new RuntimeException("user can not add into database.");
        }
        return "registered successfully.";
    }
}
