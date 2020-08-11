package com.danielfarias.CursoSpringSecurity.security;

import com.google.common.collect.Sets;

import java.util.Set;

import static com.danielfarias.CursoSpringSecurity.security.ApplicationUserPermission.*;

public enum ApplicationUserRole {
	
	STUDENT(Sets.newHashSet()), //Student pode ter 0 ou mais permissões
	ADMIN(Sets.newHashSet(COURSE_READ, COURSE_WRITE, STUDENT_READ, COURSE_WRITE)); //Admin tem todas essas permissões
	
	//Usando Set, porque a permissão deve ser unica
	private final Set<ApplicationUserPermission> permissions;

	private ApplicationUserRole(Set<ApplicationUserPermission> permissions) {
		this.permissions = permissions;
	}

	public Set<ApplicationUserPermission> getPermissions() {
		return permissions;
	}
}
