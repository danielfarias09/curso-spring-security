package com.danielfarias.CursoSpringSecurity.security;

import static com.danielfarias.CursoSpringSecurity.security.ApplicationUserRole.STUDENT;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.danielfarias.CursoSpringSecurity.auth.ApplicationUserService;
import com.danielfarias.CursoSpringSecurity.jwt.JwtConfig;
import com.danielfarias.CursoSpringSecurity.jwt.JwtTokenVerifierFilter;
import com.danielfarias.CursoSpringSecurity.jwt.JwtUsernameAndPasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true) //Ativa as anotation @PreAuthorize nos métodos da API
public class AplicationSecurityConfig extends WebSecurityConfigurerAdapter{
	
	private final PasswordEncoder passwordEncoder;
	
	private final ApplicationUserService applicationUserService;	
	
	private final SecretKey secretKey;
	
	private final JwtConfig jwtConfig;


	@Autowired
	public AplicationSecurityConfig(PasswordEncoder passwordEncoder, ApplicationUserService applicationUserService,
			SecretKey secretKey, JwtConfig jwtConfig) {
		this.passwordEncoder = passwordEncoder;
		this.applicationUserService = applicationUserService;
		this.secretKey = secretKey;
		this.jwtConfig = jwtConfig;
	}


	@Override
	protected void configure(HttpSecurity http) throws Exception{
		//OBS: A ordem que os antMatchers são definidos importa
		http
		//É recomendado usar CSRF quando a requisição do serviço pode ser procesada por um navegador
			.csrf().disable()
			.sessionManagement()
				.sessionCreationPolicy(SessionCreationPolicy.STATELESS)//JWT é statelles e sessão é a salva no banco de dados
			.and()
			.addFilter(new JwtUsernameAndPasswordAuthenticationFilter(authenticationManager(), jwtConfig, secretKey))//Um dos filtros até a requisição chegar na API
			.addFilterAfter(new JwtTokenVerifierFilter(secretKey, jwtConfig), JwtUsernameAndPasswordAuthenticationFilter.class) //Filtro a ser executado logo após o primeiro
			.authorizeRequests()
			.antMatchers("/", "index", "/css/*", "/js/*", "/login") //Todos esses arquivos os URLs
			.permitAll() //serão permitidos de serem acessados por qualquer usuário mesmo sem estarem logados
			.antMatchers("/api/**").hasRole(STUDENT.name()) //Tudo que vem depois de /api só pode ser acessado pela role STUDENT
			.anyRequest() //Qualquer requisição
			.authenticated();// Deve ser autenticada
	}
	
	
	

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.authenticationProvider(daoAuthenticationProvider());
	}


	@Bean
	public DaoAuthenticationProvider daoAuthenticationProvider() {
		DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
		provider.setPasswordEncoder(passwordEncoder);
		provider.setUserDetailsService(applicationUserService);
		return provider;
	}

	
	
	
	
}
