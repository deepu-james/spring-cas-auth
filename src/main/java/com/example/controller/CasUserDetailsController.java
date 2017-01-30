package com.example.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author Dmytro Fedonin
 *
 */
@RestController
public class CasUserDetailsController {
    private final Logger log = LoggerFactory.getLogger(CasUserDetailsController.class);

    @RequestMapping("/user")
    @ResponseBody
    public Object user() {
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        if (principal instanceof String) { // to prevent json parse error on client while going as unanimous user
            return "{}";
        }
        return principal;
    }
}
