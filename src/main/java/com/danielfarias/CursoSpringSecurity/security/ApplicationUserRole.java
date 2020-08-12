package com.danielfarias.CursoSpringSecurity.security;

import com.google.common.collect.Sets;

import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.security.core.authority.SimpleGrantedAuthority;

import static com.danielfarias.CursoSpringSecurity.security.ApplicationUserPermission.*;

public enum ApplicationUserRole {
	
	STUDENT(Sets.newHashSet()), //Student pode ter 0 ou mais permissões
	ADMIN(Sets.newHashSet(COURSE_READ, COURSE_WRITE, STUDENT_READ, STUDENT_WRITE)), //Admin tem todas essas permissões
	ADMIN_TRAINEE(Sets.newHashSet(COURSE_READ, STUDENT_READ));
	
	//Usando Set, para não haver permissões duplicadas
	private final Set<ApplicationUserPermission> permissions;

	private ApplicationUserRole(Set<ApplicationUserPermission> permissions) {
		this.permissions = permissions;
	}

	public Set<ApplicationUserPermission> getPermissions() {
		return permissions;
	}
	
	public Set<SimpleGrantedAuthority> getGrantedAuthorities(){
		Set<SimpleGrantedAuthority> permissions =  getPermissions().stream()
			.map(permission -> new SimpleGrantedAuthority(permission.getPermission()))
			.collect(Collectors.toSet());
		
		permissions.add(new SimpleGrantedAuthority("ROLE_" + this.name() ));
		return permissions;
	}
}
