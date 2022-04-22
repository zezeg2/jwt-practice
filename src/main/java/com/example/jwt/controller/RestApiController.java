package com.example.jwt.controller;

import com.example.jwt.model.user.User;
import com.example.jwt.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

//@CrossOrigin
@RestController
@RequiredArgsConstructor
public class RestApiController {

    private final UserService userService;

    @GetMapping("home")
    public String home(){
        return "<h1>Home</h1>";
    }

    @PostMapping("token")
    public String token(){
        return "<h1>token</h1>";
    }

    @PostMapping("join")
    public String join (@RequestBody User user ){
        return userService.join(user);
    }

    //user, manager, admin
    @GetMapping("api/v1/user")
    public String user(){
        return "user";
    }
    //manager, admin
    @GetMapping("api/v1/manager")
    public String manager(){
        return "manager";
    }
    //admin
    @GetMapping("api/v1/admin")
    public String admin(){
        return "admin";
    }
}
