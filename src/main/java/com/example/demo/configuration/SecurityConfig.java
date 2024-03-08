package com.example.demo.configuration;

import java.net.PasswordAuthentication;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.AuthorizeHttpRequestsDsl;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
public class SecurityConfig {
	
	
	@Bean
	public ClientRegistrationRepository clientRegistrationRepository() {
		return new InMemoryClientRegistrationRepository(this.clientRegistration());
	}
	
	
	
	
	private ClientRegistration clientRegistration() {
		return ClientRegistration.withRegistrationId("github").
				clientId("66a51d23ab743bd1d8ad")
				.clientSecret("32dc74d7d9cbd4e20bfca60e838829590f3a4f67")
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.scope("read")
				.authorizationUri("https://github.com/login/oauth/authorize")
				.tokenUri("https://github.com/login/oauth/access_token")
				.userInfoUri("https://api.github.com/user")
				.userNameAttributeName("id")
				.clientName("Developer coading")
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.redirectUri("{baseUrl}/login/oauth2/code{registrationId}")
				.build(); 	
	}
	
	
	
	
	
	
@Bean
public UserDetailsService detailsService() {
	UserDetails user= User.withUsername("Aliyu").password("1234").authorities("read").build();
	return new InMemoryUserDetailsManager(user);	
}
@Bean
public PasswordEncoder passwordEncoder() {
	return NoOpPasswordEncoder.getInstance();
}

@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
	http.csrf(
			
			c->c.disable()
			)
	       .authorizeHttpRequests(
					request -> request.requestMatchers("/css/**","/oauth2/**").permitAll().anyRequest().authenticated()				
					)
	       .formLogin(
	    		       		   
	    		   form -> form.loginPage("/login").permitAll()
	    		   .loginProcessingUrl("/login")
	    		   .defaultSuccessUrl("/home")	    		     
	    		   )
	       
	       .oauth2Login(
	    		   form-> form.loginPage("/login").permitAll().defaultSuccessUrl("/home")
	    		   )
	       
	       .logout(
	    		   
	    		   form-> form.invalidateHttpSession(true).clearAuthentication(true)
	    		   .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
	    		   .logoutSuccessUrl("/login?logout")
	    		   .permitAll()
	    		   );
	       
	       
	       
	       
	     return http.build();
}



}
