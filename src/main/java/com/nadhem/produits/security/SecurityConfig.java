package com.nadhem.produits.security;
import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	
	@Bean
	public PasswordEncoder passwordEncoder () {
	return new BCryptPasswordEncoder();
	}
	
	@Autowired
	private DataSource dataSource;
	@Autowired
	UserDetailsService userDetailsService;
	
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {

	PasswordEncoder passwordEncoder = passwordEncoder ();
	auth.inMemoryAuthentication().withUser("admin")
	.password(passwordEncoder.encode("123")).roles("ADMIN");
	auth.inMemoryAuthentication().withUser("nadhem")
	.password(passwordEncoder.encode("123")).roles("AGENT","USER");
	auth.inMemoryAuthentication().withUser("user1")
	.password(passwordEncoder.encode("123")).roles("USER");}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
	http.authorizeRequests().anyRequest().authenticated();
	http.formLogin();
	http.exceptionHandling().accessDeniedPage("/accessDenied");
	}
	}