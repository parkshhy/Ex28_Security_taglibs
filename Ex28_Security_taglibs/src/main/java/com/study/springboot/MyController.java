package com.study.springboot;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class MyController {

	
	//루트(/)에 대한 url호출을 처리하고 있다.
	@RequestMapping("/")
	public @ResponseBody String root() throws Exception{
		return "Security-LoginForm(3)";
	}

	//guest 하위에 대한 url 호출을 처리하고 있다.
	@RequestMapping("/guest/welcome")
	public String welcome1() {
		
		return "guest/welcome1";
	}

	//member 하위에 대한 url호출을 처리하고 있다.
	@RequestMapping("/member/welcome")
	public String welcome2() {
		return "member/welcome2";
		
	}
	
	//admin 하위에 대한 url호출을 처리하고 있다.
	@RequestMapping("/admin/welcome")
	public String welcome3() {
		return "admin/welcome3";
	}
	
	@RequestMapping("/loginForm")
	public String loginForm() {
		return "security/loginForm";
		
	}
	

}

