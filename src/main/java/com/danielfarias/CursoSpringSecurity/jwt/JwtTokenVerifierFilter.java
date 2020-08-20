package com.danielfarias.CursoSpringSecurity.jwt;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import javax.crypto.SecretKey;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import com.google.common.base.Strings;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;

//Filtro responsável por verificar e validar o Token
public class JwtTokenVerifierFilter extends OncePerRequestFilter{
	
	private final SecretKey secretKey;
	
	private final JwtConfig jwtConfig;
	

	public JwtTokenVerifierFilter(SecretKey secretKey, JwtConfig jwtConfig) {
		this.secretKey = secretKey;
		this.jwtConfig = jwtConfig;
	}


	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		
		String authorizationHeader = request.getHeader(jwtConfig.getAuthorizationHeader());
		
		if(Strings.isNullOrEmpty(authorizationHeader) || !authorizationHeader.startsWith(jwtConfig.getTokenPrefix())) {
			filterChain.doFilter(request, response);
			return; //A requisição é rejeitada caso o Authorization Header vier vazio ou não iniciar com a String 'Bearer'
		}
		
		try {
			String token = authorizationHeader.replace(jwtConfig.getTokenPrefix(), "");
			
			Jws<Claims> claimsJws = Jwts.parser()
				.setSigningKey(secretKey)
				.parseClaimsJws(token);
			
			Claims body = claimsJws.getBody();
			
			String username = body.getSubject();
			
			List<Map<String, String>> authorities = (List<Map<String, String>>) body.get("authorities");//Retorna uma lista de maps
			
			Set<SimpleGrantedAuthority> simpleGrantedAuthorities = authorities.stream() //Convertendo para o tipo esperado pelo construtor
				.map(m -> new SimpleGrantedAuthority(m.get("authority")))
				.collect(Collectors.toSet());
			
			Authentication authentication = new UsernamePasswordAuthenticationToken(
					username,
					null,
					simpleGrantedAuthorities
			);
			
			//Se tudo estiver ok e o token for validado, o usuário será autenticado
			SecurityContextHolder.getContext().setAuthentication(authentication);
				
		}catch(JwtException e) {
			//Entra aqui se o token for validao ou estiver expirado
			throw new IllegalStateException("O token não pôde ser validado");
		}
		
		filterChain.doFilter(request, response); //Passa o request e response para o próximo filtro
		
	}

}
