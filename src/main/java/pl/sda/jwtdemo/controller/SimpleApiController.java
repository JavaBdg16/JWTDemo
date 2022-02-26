package pl.sda.jwtdemo.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/simple")
public class SimpleApiController {

    // /api/simple/open
    @GetMapping("/open")
    public String openMethod() {
        return "open";
    }

    // /api/simple/auth
    @GetMapping("/auth")
    public String authMethod() {
        return "auth";
    }
}
