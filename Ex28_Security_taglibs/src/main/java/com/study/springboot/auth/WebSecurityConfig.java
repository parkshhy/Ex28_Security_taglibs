package com.study.springboot.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;


//@Configuration 어노테이션은 이 클래스를 빈으로 등록하는데 스프링 설정으로 사용한다는 의미
@Configuration

//@EnableWebSecurity 어노테이션은 스프링 시큐리티의 기능을 활성화 하겠다는 의미이다.
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter{

	
	@Autowired
	public AuthenticationFailureHandler authenticationFailureHandler;
	
	
	@Override
	protected void configure(HttpSecurity http) throws Exception{
		http.authorizeRequests()
		//루트(/)url 요청에 대해서 모두에게 허용하는 세팅을 한다.
		.antMatchers("/").permitAll()
		
		///css 아래 모든 url요청,/js 아래 모든 url 요청 및 /img 아래 모든 url 요청에 대해서는 모두에게 허용하는 세팅을 한다
		.antMatchers("/css/**","/js/**","/img/**").permitAll()
		
		///guest 아래 모든 url요청에 대해서 모두에게 허용하는 세팅을 한다
		.antMatchers("/guest/**").permitAll()
		
		//member 아래 url 요청은 'USER'나,'ADMIN'역할(role)을 가지고 있어야 한다고 세팅을 한다
		.antMatchers("/member/**").hasAnyRole("USER","ADMIN")
		
		//로그인 폼 url은 모두에게 허용하는 세팅을 한다
		.antMatchers("/admin/**").hasRole("ADMIN")
		
		//로그아웃 url요청은 모두에게 허용하는 세팅을 한다
		.anyRequest().authenticated();
		
		http.formLogin()
				.loginPage("/loginForm") // default : /login
				.loginProcessingUrl("/j_spring_security_check")
				//.failureUrl("/loginForm?error") //login?error 
				.failureHandler(authenticationFailureHandler)
				//.defaultSuccessUrl("/")
				.usernameParameter("j_username") //default :j_username
				.passwordParameter("j_password") //default :j_password
		
				.permitAll();
		
		
		http.logout()
				.logoutUrl("/logout") //default
				.logoutSuccessUrl("/")
				.permitAll();
	
			http.csrf().disable();
	}
	
	@Autowired
	public void configureGlobal(AuthenticationManagerBuilder auth) throws
	Exception{
		auth.inMemoryAuthentication()
			.withUser("user").password(passwordEncoder().encode("1234")).
			roles("USER")
			.and()
			.withUser("admin").password(passwordEncoder().encode("1234")).
			roles("ADMIN");
			//ROLE_ADMIN 에서 ROLE_는 자동으로 붙는다.
	}
		
	
	
	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
	return new BCryptPasswordEncoder();	
		
	}
	
}
