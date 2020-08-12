package com.danielfarias.CursoSpringSecurity.security;

import static com.danielfarias.CursoSpringSecurity.security.ApplicationUserRole.ADMIN;
import static com.danielfarias.CursoSpringSecurity.security.ApplicationUserRole.ADMIN_TRAINEE;
import static com.danielfarias.CursoSpringSecurity.security.ApplicationUserRole.STUDENT;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true) //Ativa as anotation @PreAuthorize nos métodos da API
public class AplicationSecurityConfig extends WebSecurityConfigurerAdapter{
	
	private final PasswordEncoder passwordEncoder;
	
	@Autowired
	public AplicationSecurityConfig(PasswordEncoder passwordEncoder) {
		this.passwordEncoder = passwordEncoder;
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception{
		//OBS: A ordem que os antMatchers são definidos importa
		http
			.csrf().disable()
			.authorizeRequests()
			.antMatchers("/", "index", "/css/*", "/js/*") //Todos esses arquivos os URLs
			.permitAll() //serão permitidos de serem acessados por qualquer usuário mesmo sem estarem logados
			.antMatchers("/api/**").hasRole(STUDENT.name()) //Tudo que vem depois de /api só pode ser acessado pela role STUDENT
			//Só pode executar esses métodos http em /management/api quem possui a permissão de COURSE_WRITE
				/*
				 * .antMatchers(HttpMethod.DELETE,
				 * "/management/api/**").hasAnyAuthority(ApplicationUserPermission.COURSE_WRITE.
				 * getPermission()) .antMatchers(HttpMethod.POST,
				 * "/management/api/**").hasAnyAuthority(ApplicationUserPermission.COURSE_WRITE.
				 * getPermission()) .antMatchers(HttpMethod.PUT,
				 * "/management/api/**").hasAnyAuthority(ApplicationUserPermission.COURSE_WRITE.
				 * getPermission()) //Só pode executar o método GET em /management/api quem tem
				 * a role de ADMIN e ADMIN_TRAINEE .antMatchers(HttpMethod.GET,
				 * "/management/api/**").hasAnyRole(ADMIN.name(), ADMIN_TRAINEE.name())
				 */
			.anyRequest() //Qualquer requisição
			.authenticated()// Deve ser autenticada
			.and()
			.httpBasic();// E o mecanisco de autenticação deve ser o Basic Authentication
		    //onde o password é enviado em cada requisição	
	}

	@Override
	@Bean
    //Método para recuperar os usuários do banco de dados
	protected UserDetailsService userDetailsService() {
		//Obrigatoriamente um password deve ser codificado, segundo o spring
	UserDetails danielUser = User.builder()
			.username("daniel")
			.password(passwordEncoder.encode("123456"))
			//.roles(STUDENT.name()) //ROLE_STUDENT internamente
			.authorities(STUDENT.getGrantedAuthorities())
			.build();
	
	UserDetails IzabelUser = User.builder()
			.username("izabel")
			.password(passwordEncoder.encode("123456"))
			//.roles(ADMIN.name()) //ADMIN_STUDENT 
			.authorities(ADMIN.getGrantedAuthorities())
			.build();
	
	UserDetails LuizianeUser = User.builder()
			.username("luiziane")
			.password(passwordEncoder.encode("123456"))
			//.roles(ADMIN_TRAINEE.name()) //ROLE_ADMIN_STUDENT 
			.authorities(ADMIN_TRAINEE.getGrantedAuthorities())
			.build();
	
	return new InMemoryUserDetailsManager(danielUser, IzabelUser, LuizianeUser);
	}
	
	
	
}
