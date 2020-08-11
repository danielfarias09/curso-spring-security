package com.danielfarias.CursoSpringSecurity.security;

import static com.danielfarias.CursoSpringSecurity.security.ApplicationUserRole.*;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
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
public class AplicationSecurityConfig extends WebSecurityConfigurerAdapter{
	
	private final PasswordEncoder passwordEncoder;
	
	@Autowired
	public AplicationSecurityConfig(PasswordEncoder passwordEncoder) {
		this.passwordEncoder = passwordEncoder;
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception{
		http
			.authorizeRequests()
			.antMatchers("/", "index", "/css/*", "/js/*") //Todos esses arquivos os URLs
			.permitAll() //serão permitidos de serem acessados por qualquer usuário mesmo sem estarem logados
			.antMatchers("/api/**").hasRole(STUDENT.name()) //Tudo que vem depois de /api só pode ser acessado pela role STUDENT
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
			.roles(STUDENT.name()) //ROLE_STUDENT internamente
			.build();
	
	UserDetails IzabelUser = User.builder()
			.username("izabel")
			.password(passwordEncoder.encode("123456"))
			.roles(ADMIN.name()) //ADMIN_STUDENT internamente
			.build();
	
	return new InMemoryUserDetailsManager(danielUser, IzabelUser);
	}
	
	
	
}
