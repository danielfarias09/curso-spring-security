package com.danielfarias.CursoSpringSecurity.user;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UserServiceImpl implements UserService{

    private final UserRepository userRepository;

    private final PasswordEncoder encoder;

    @Autowired
    public UserServiceImpl(UserRepository userRepository, PasswordEncoder encoder) {
        this.userRepository = userRepository;
        this.encoder = encoder;
    }

    @Override
    public User save(UserDTO userDTO) {
        User user = new User(userDTO.getName(), userDTO.getEmail(), encoder.encode(userDTO.getPassword()), userDTO.getRole());
        return userRepository.save(user);
    }
}
