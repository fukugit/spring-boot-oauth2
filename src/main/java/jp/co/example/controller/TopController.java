package jp.co.example.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class TopController {

    @RequestMapping("/")
    public String hello() {
        return "top";
    }
}
