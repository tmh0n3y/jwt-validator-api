package com.github.tmh0n3y;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController 
public class AuthController {

    @GetMapping("/auth")
    public String auth() {
        return "Hello world!";
    }
    
}
