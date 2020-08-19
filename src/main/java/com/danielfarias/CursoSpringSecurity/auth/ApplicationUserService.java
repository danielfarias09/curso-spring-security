package com.danielfarias.CursoSpringSecurity.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class ApplicationUserService implements UserDetailsService{
	
	private final ApplicationUserDao applicationUserDao;
	

	@Autowired
	public ApplicationUserService(@Qualifier("fake") ApplicationUserDao applicationUserDao) {//Uso o @Qualifier para dizer explicitamente que eu quero intanciar essa implementação de ApplicationUserDao
		this.applicationUserDao = applicationUserDao;
	}


	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		return applicationUserDao.selectApplicationUserByUsername(username)
				.orElseThrow(() -> new UsernameNotFoundException(String.format("Username %s not found", username)));
	}

}
