package com.example.demo.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@Controller
public class Usercontroller {

	@GetMapping("/home")
	
	public String home() {
		return"home";
	}
	
	@GetMapping("/login")
	public String login() {
		return "login";
	}
	
	
	
}
