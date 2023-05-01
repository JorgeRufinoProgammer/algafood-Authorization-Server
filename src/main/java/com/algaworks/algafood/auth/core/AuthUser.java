package com.algaworks.algafood.auth.core;

import java.util.Collections;

import org.springframework.security.core.userdetails.User;

import com.algaworks.algafood.auth.domain.Usuario;

import lombok.Getter;

//Estendemos a classe "User" que é um "UserDetails" para ser utilizada na classe "JpaUserDetailsService"
@Getter
public class AuthUser extends User{
	private static final long serialVersionUID = 1L;
	
	private String fullName;
	
//	A senha precisa está cryptografada no banco de dados (site Bcrypt-generator)
	public AuthUser(Usuario usuario) {
		super(usuario.getEmail(), usuario.getSenha(), Collections.emptyList());
		
		this.fullName = usuario.getNome();
	}
}
