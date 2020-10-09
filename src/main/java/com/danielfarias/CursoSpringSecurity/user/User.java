package com.danielfarias.CursoSpringSecurity.user;

import com.danielfarias.CursoSpringSecurity.security.ApplicationUserRole;

import javax.persistence.*;

@Entity
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    private String name;

    private String email;

    private String password;

    @Enumerated(EnumType.STRING)
    private ApplicationUserRole role;

    public User() {
    }

    public User(String name, String email, String password, ApplicationUserRole role) {
        this.name = name;
        this.email = email;
        this.password = password;
        this.role = role;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public ApplicationUserRole getRole() {
        return role;
    }

    public void setRole(ApplicationUserRole role) {
        this.role = role;
    }
}
