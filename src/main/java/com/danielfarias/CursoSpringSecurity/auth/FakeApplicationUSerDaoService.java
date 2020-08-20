package com.danielfarias.CursoSpringSecurity.auth;

import static com.danielfarias.CursoSpringSecurity.security.ApplicationUserRole.STUDENT;
import static com.danielfarias.CursoSpringSecurity.security.ApplicationUserRole.ADMIN;
import static com.danielfarias.CursoSpringSecurity.security.ApplicationUserRole.ADMIN_TRAINEE;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import com.google.common.collect.Lists;

@Repository("fake") //Dou esse nome ao Repository para o caso de precisar trocar a implementação da interface. 
public class FakeApplicationUSerDaoService  implements ApplicationUserDao{
	
	private  final PasswordEncoder passwordEncoder;

	@Autowired
	public FakeApplicationUSerDaoService(PasswordEncoder passwordEncoder) {
		this.passwordEncoder = passwordEncoder;
	}
	

	@Override
	public Optional<ApplicationUser> selectApplicationUserByUsername(String username) {
		return getApplicationUsers().stream().filter(user -> user.getUsername().equals(username)).findFirst();
	}
	

	//Simula o acesso ao banco de dados
	private List<ApplicationUser> getApplicationUsers(){
		List<ApplicationUser> applicationUsers = Lists.newArrayList(
				new ApplicationUser(
						STUDENT.getGrantedAuthorities(),
						"daniel",
						passwordEncoder.encode("123456"),//Obrigatoriamente um password deve ser codificado, segundo o spring
						true,
						true,
						true,
						true
					),		
				new ApplicationUser(
						ADMIN.getGrantedAuthorities(),
						"izabel",
						passwordEncoder.encode("123456"),
						true,
						true,
						true,
						true
					),
				new ApplicationUser(
						ADMIN_TRAINEE.getGrantedAuthorities(),
						"luiziane",
						passwordEncoder.encode("123456"),
						true,
						true,
						true,
						true
					)
		);
		
		return applicationUsers;
	}

}
