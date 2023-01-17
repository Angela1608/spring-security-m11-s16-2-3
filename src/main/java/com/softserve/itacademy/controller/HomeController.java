package com.softserve.itacademy.controller;

import com.softserve.itacademy.service.UserService;
import com.softserve.itacademy.service.security.MyUserDetails;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class HomeController {
    private final UserService userService;

    public HomeController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping({"/", "home"})
    public String home(Model model, Authentication auth) {
        MyUserDetails userDetails = (MyUserDetails) auth.getPrincipal();
        if (!userDetails.getUserAuthority().equals("ADMIN")) {
            return "redirect:/todos/all/users/" + userDetails.getUserId();
        }
        model.addAttribute("users", userService.getAll());
        return "home";
    }
}
