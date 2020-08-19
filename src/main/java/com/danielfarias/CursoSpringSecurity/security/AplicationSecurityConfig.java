package com.danielfarias.CursoSpringSecurity.security;

import static com.danielfarias.CursoSpringSecurity.security.ApplicationUserRole.ADMIN;
import static com.danielfarias.CursoSpringSecurity.security.ApplicationUserRole.ADMIN_TRAINEE;
import static com.danielfarias.CursoSpringSecurity.security.ApplicationUserRole.STUDENT;

import java.util.concurrent.TimeUnit;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import com.danielfarias.CursoSpringSecurity.auth.ApplicationUserService;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true) //Ativa as anotation @PreAuthorize nos métodos da API
public class AplicationSecurityConfig extends WebSecurityConfigurerAdapter{
	
	private final PasswordEncoder passwordEncoder;
	
	private final ApplicationUserService applicationUserService;	
	
	@Autowired
	public AplicationSecurityConfig(PasswordEncoder passwordEncoder, ApplicationUserService applicationUserService) {
		this.passwordEncoder = passwordEncoder;
		this.applicationUserService = applicationUserService;
	}


	@Override
	protected void configure(HttpSecurity http) throws Exception{
		//OBS: A ordem que os antMatchers são definidos importa
		http
		//É recomendado usar CSRF quando a requisição do serviço pode ser procesada por um navegador
			.csrf().disable()
			.authorizeRequests()
			.antMatchers("/", "index", "/css/*", "/js/*", "/login") //Todos esses arquivos os URLs
			.permitAll() //serão permitidos de serem acessados por qualquer usuário mesmo sem estarem logados
			.antMatchers("/api/**").hasRole(STUDENT.name()) //Tudo que vem depois de /api só pode ser acessado pela role STUDENT
			.anyRequest() //Qualquer requisição
			.authenticated()// Deve ser autenticada
			.and()
			.formLogin()// O usuário loga através de um formulário 
			//O servidor valida as credenciais do usuário e salva o sessionId nos cookies.
		    //A cada requisição, é utilizado esse sessionId salvo nos cookies (expira em 30 minutos de inatividade)
		    //Servidor valida o sessionId e retorna o recurso caso esteja tudo ok.
				.loginPage("/login")//Sobrescreve a página de login padrão do spring security
				.defaultSuccessUrl("/courses", true)// Redireciona para essa página logo após o login com sucesso
				.usernameParameter("username")//altera os nomes dos parâmetros padrões do formulário de Login
				.passwordParameter("password")
			.and()
			 //Ativa a funcionalidade de remember me que dura 2 semanas  salva nos cookies (Você não precisa fazer login novamente durante esse período)
			.rememberMe()// enviar como respota o cookie de nome 'remember-me'
				.tokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(21)) //Aumenta a validade do rememberme
				.key("umaChaveSegura") //Chave utilizada para gerar o token
				.rememberMeParameter("remember-me") //altera o nome do parâmetro remember-me
			.and()
			.logout()//Altera o comportamento do logout
				.logoutUrl("/logout")
				.clearAuthentication(true)
				.invalidateHttpSession(true)
				.deleteCookies("JSESSIONID", "remember-me")
				.logoutSuccessUrl("/login");		
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
