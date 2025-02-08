package br.com.hansensoft.apibackend.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.GetMapping;


@RestController
@RequestMapping("/api/test")
public class ApiController {

    @GetMapping
    public String test() {
        return "Hello, World!";
    }
}
