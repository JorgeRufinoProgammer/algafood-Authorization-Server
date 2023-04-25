package com.algaworks.algafood.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;

@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter{
	
	@Autowired
	private PasswordEncoder passwordEncoder;
	
	@Autowired
	private AuthenticationManager authenticationManager;
	
//	Refresh token precisa deste service
	@Autowired
	private UserDetailsService userDetailsService;
	
//	Esses dados devem ser passados em "Authorization" dentro do Postman. São os dados do cliente.
	
	@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
		clients.inMemory()
					.withClient("algafood-web")							//Cliente Web
					.secret(passwordEncoder.encode("web123"))
					.authorizedGrantTypes("password", "refresh_token")	//Fluxo de Password / Refresh Token (Por padrão, expira em 30 Dias)
					.scopes("write", "read")
					.accessTokenValiditySeconds(60 * 60 * 6)			//6 horas
					.refreshTokenValiditySeconds(60 * 24 * 60 * 60)		//60 dias				
				.and()
					.withClient("faturamento")							//Cliente de aplicacao backend  que irá consultar a API
					.secret(passwordEncoder.encode("faturamento123"))
					.authorizedGrantTypes("client_credentials")
					.scopes("write", "read")
					
//	Link para acessar no navegador: http://auth.algafood.local:8081/oauth/authorize?response_type=code&client_id=foodanalytics&state=abc&redirect_uri=http://aplicacao-cliente
//	Irá aparecer a tela para logar, e em seguida autorizar os acessos do cliente "foodanalytics", depois de autorizar, ele irá gera o "code" que será utilizado
//	para solicitar um "AcessToken" para então poder utilizar a API AlgaFood
					
				.and()
					.withClient("foodanalytics")
					.secret(passwordEncoder.encode("food123"))
					.authorizedGrantTypes("authorization_code")
					.scopes("write", "read")
					.redirectUris("http://www.foodanalytics.local:8082")
				.and()									 //Exemplo luxo Implicit Grant Type (não recomendado pois o token vai na URI)
					.withClient("webadmin")
					.authorizedGrantTypes("implicit")
					.scopes("write", "read")
					.redirectUris("http://aplicacao-cliente")
				.and()
					.withClient("checktoken")
						.secret(passwordEncoder.encode("check123"));
	}

	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
		endpoints
			.authenticationManager(authenticationManager)
			.userDetailsService(userDetailsService)
			.reuseRefreshTokens(false); 	//Toda vez que um RefreshToken for utilizado, será criado um novo RefreshToken no lugar do utilizado 
	}
	
	@Override
	public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
		security.checkTokenAccess("isAuthenticated()");	//Expressao do Spring Security para liberar acesso se estiver autenticado
//		security.checkTokenAccess("permiteAll()");		//Expressao do Spring Security para liberar acesso sem estar autenticado
	}
	
}
