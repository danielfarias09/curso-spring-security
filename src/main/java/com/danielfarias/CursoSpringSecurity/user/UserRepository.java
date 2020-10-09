package com.danielfarias.CursoSpringSecurity.user;

import com.danielfarias.CursoSpringSecurity.user.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    User getByEmail(String email);
}
