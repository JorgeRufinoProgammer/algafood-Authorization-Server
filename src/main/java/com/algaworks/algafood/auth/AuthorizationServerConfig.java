package com.algaworks.algafood.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;

@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter{
	
	@Autowired
	private PasswordEncoder passwordEncoder;
	
	@Autowired
	private AuthenticationManager authenticationManager;
	
//	Esses dados devem ser passados em "Authorization" dentro do Postman. São os dados do cliente.
	
	@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
		clients.inMemory()
					.withClient("algafood-web")					//Cliente Web
					.secret(passwordEncoder.encode("web123"))
					.authorizedGrantTypes("password")			//Fluxo de Password
					.scopes("write", "read")
					.accessTokenValiditySeconds(60 * 60 * 6);	//Tempo de expiração do token (em segundos). Neste caso configurado em 6hs
//				.and()
//					.withClient("app-mobile")					//Cliente Mobile
//					.secret(passwordEncoder.encode("mob123"))	
//					.authorizedGrantTypes("password", "outroGrandType")			//Fluxo de Password
//					.scopes("write", "read");
	}

	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
		endpoints.authenticationManager(authenticationManager);
	}
	
}
