package com.danielfarias.CursoSpringSecurity.security;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
public class AplicationSecurityConfig extends WebSecurityConfigurerAdapter{

	@Override
	protected void configure(HttpSecurity http) throws Exception{
		http
			.authorizeRequests()
			.antMatchers("/", "index", "/css/*", "/js/*", "/api/v1/students/*") //Todos esses arquivos os URLs
			.permitAll() //serão permitidos de serem acessados por qualquer usuário mesmo sem estarem logados
			.anyRequest() //Qualquer requisição
			.authenticated()// Deve ser autenticada
			.and()
			.httpBasic();// E o mecanisco de autenticação deve ser o Basic Authentication
		    //onde o password é enviado em cada requisição	
	}
	
}
