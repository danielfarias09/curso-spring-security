package com.danielfarias.CursoSpringSecurity.security;

import static com.danielfarias.CursoSpringSecurity.security.ApplicationUserRole.ADMIN;
import static com.danielfarias.CursoSpringSecurity.security.ApplicationUserRole.ADMIN_TRAINEE;
import static com.danielfarias.CursoSpringSecurity.security.ApplicationUserRole.STUDENT;

import java.util.concurrent.TimeUnit;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

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
