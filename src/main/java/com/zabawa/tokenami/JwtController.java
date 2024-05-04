package com.zabawa.tokenami;

import lombok.AllArgsConstructor;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AllArgsConstructor
public class JwtController {

    private JwtService jwtService;

    @GetMapping("/token")
    public String getToken(@RequestParam String username) {
        return jwtService.generateToken(username);
    }
}
