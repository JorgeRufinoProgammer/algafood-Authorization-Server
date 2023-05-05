package com.algaworks.algafood.auth.core;

import java.util.Arrays;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.CompositeTokenGranter;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.approval.ApprovalStore;
import org.springframework.security.oauth2.provider.approval.TokenApprovalStore;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;

@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter{
	
	@Autowired
	private AuthenticationManager authenticationManager;
	
//	Refresh token precisa deste service
	@Autowired
	private UserDetailsService userDetailsService;
	
	@Autowired
	private JwtKeyStoreProperties jwtKeyStoreProperties; 

//	Fonte de dados
	@Autowired
	private DataSource dataSource;
	
//	Esses dados devem ser passados em "Authorization" dentro do Postman. São os dados do cliente.
	
	@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
		clients.jdbc(dataSource);
	}

	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
		
//		Cadeia de Enhancers
		var enhancerChain = new TokenEnhancerChain();
		
//		Primeiro adiconamos os nosso custom enhancers e por ultimo o TokenCoverter
		enhancerChain.setTokenEnhancers(Arrays.asList(new JwtCustomClaimsTokenEnhancer(), jwtAccessTokenConverter()));
		
		endpoints
			.authenticationManager(authenticationManager)
			.userDetailsService(userDetailsService)
			.reuseRefreshTokens(false) 							//Toda vez que um RefreshToken for utilizado, será criado um novo RefreshToken no lugar do utilizado
			.accessTokenConverter(jwtAccessTokenConverter())	//Adiciona o metodo conversor JWT
			.tokenEnhancer(enhancerChain)						//Passamos a cadeia/lista de "enhancers"
			.approvalStore(aprovalStore(endpoints.getTokenStore()))
			.tokenGranter(tokenGranter(endpoints));				//Chama o metodo para adicionar o PKCE aos tipos de tokens suportados
	}
	
//	Configura a permissao de aprovaçao dos escopos/scopes configurados
	private ApprovalStore aprovalStore(TokenStore tokenStore) {
		var approvalStore = new TokenApprovalStore();
		approvalStore.setTokenStore(tokenStore);
		
		return approvalStore;
	}

	@Override
	public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
//		security.checkTokenAccess("isAuthenticated()")		//Expressao do Spring Security para liberar acesso se estiver autenticado
		security.checkTokenAccess("permitAll()")			//Expressao do Spring Security para liberar acesso sem estar autenticado
					.tokenKeyAccess("permitAll")			//Gera a chave publica por um "GET" no endpoint ("/token_key"). Exluir os "\n" dentro da chave
					.allowFormAuthenticationForClients();	//Permite autenticacao pelo "body" em vez de usar o "httpBase"	
	}
	
//	Instancia do PKCE aos tokens
	private TokenGranter tokenGranter(AuthorizationServerEndpointsConfigurer endpoints) {
		var pkceAuthorizationCodeTokenGranter = new PkceAuthorizationCodeTokenGranter(endpoints.getTokenServices(),
				endpoints.getAuthorizationCodeServices(), endpoints.getClientDetailsService(),
				endpoints.getOAuth2RequestFactory());
		
		var granters = Arrays.asList(
				pkceAuthorizationCodeTokenGranter, endpoints.getTokenGranter());
		
		return new CompositeTokenGranter(granters);
	}
	
	@Bean
	public JwtAccessTokenConverter jwtAccessTokenConverter() {
		var jwtAccessTokenConverter = new JwtAccessTokenConverter();
	    
	    var jksResource = new ClassPathResource(jwtKeyStoreProperties.getPath());
	    var keyStorePass = jwtKeyStoreProperties.getPassword();
	    var keyPairAlias = jwtKeyStoreProperties.getKeypairAlias();
	    
	    var keyStoreKeyFactory = new KeyStoreKeyFactory(jksResource, keyStorePass.toCharArray());
	    var keyPair = keyStoreKeyFactory.getKeyPair(keyPairAlias);
	    
	    jwtAccessTokenConverter.setKeyPair(keyPair);
	    
	    return jwtAccessTokenConverter;
	}
}
