package com.algaworks.algafood.auth.core;

import java.util.HashMap;

import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;

public class JwtCustomClaimsTokenEnhancer implements TokenEnhancer{

	@Override
	public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
		
//		Garantimos que a autenticacao é de um usuario pois se for um ClientCredentials não será uma instancia de AuthUser
		if (authentication.getPrincipal() instanceof AuthUser) {
			
	//		Pega o Usuario(AuthUser) 
				var authUser = (AuthUser) authentication.getPrincipal();
				
				var info = new HashMap<String, Object>();
				info.put("nome-completo", authUser.getFullName());
				info.put("usuario-id", authUser.getUserId());
				
	//		Estamos pegando a implementacao do "OAuth2AccessToken" para poder utilizar o metodo para adicionar o que queremos
				var oAuth2AccessToken = (DefaultOAuth2AccessToken) accessToken;
				oAuth2AccessToken.setAdditionalInformation(info);		//Adicionamso o nome completo nas informaçoes do Token	
		}
		
		return accessToken;
	}

}
