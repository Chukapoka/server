package com.chukapoka.server.user.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Controller
public class OAuthController {

    @RequestMapping("/auth/login")
    public String login() {
        return "login";
    }


    @GetMapping("/auth/success")
    public String auth() {
        return "loginSuccess";
    }
}
