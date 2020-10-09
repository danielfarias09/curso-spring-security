package com.danielfarias.CursoSpringSecurity.user;

import com.danielfarias.CursoSpringSecurity.security.ApplicationUserRole;

public class UserDTO {

    private String name;

    private String email;

    private String password;

    private ApplicationUserRole role;

    public UserDTO(String name, String email, String password, ApplicationUserRole role) {
        this.name = name;
        this.email = email;
        this.password = password;
        this.role = role;
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
