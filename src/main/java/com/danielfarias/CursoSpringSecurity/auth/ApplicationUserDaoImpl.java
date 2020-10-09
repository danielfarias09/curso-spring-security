package com.danielfarias.CursoSpringSecurity.auth;

import com.danielfarias.CursoSpringSecurity.user.User;
import com.danielfarias.CursoSpringSecurity.user.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

@Repository("userDao")
public class ApplicationUserDaoImpl implements ApplicationUserDao{

    private final UserRepository userRepository;

    @Autowired
    public ApplicationUserDaoImpl(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public Optional<ApplicationUser> selectApplicationUserByUsername(String email) {
        Set<GrantedAuthority> authorities = new HashSet<>();
        User user = userRepository.getByEmail(email);
        return Optional.of(new ApplicationUser(
                user.getRole().getGrantedAuthorities(),
                user.getEmail(),
                user.getPassword(),
                true,
                true,
                true,
                true
        ));
    }

}
