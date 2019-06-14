package com.github.reubuisnessgame.gamebank.authservice.controller;

import com.github.reubuisnessgame.gamebank.authservice.form.AuthForm;
import com.github.reubuisnessgame.gamebank.authservice.model.Role;
import com.github.reubuisnessgame.gamebank.authservice.model.UserModel;
import com.github.reubuisnessgame.gamebank.authservice.repository.UserRepository;
import com.github.reubuisnessgame.gamebank.authservice.security.jwt.JwtTokenProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

import static org.springframework.http.ResponseEntity.ok;

@RestController
@RequestMapping("/login")
public class AuthController {

    private final AuthenticationManager authenticationManager;

    private final
    JwtTokenProvider jwtTokenProvider;

    private final
    UserRepository userRepository;

    @Autowired
    public AuthController(JwtTokenProvider jwtTokenProvider, UserRepository userRepository, AuthenticationManager authenticationManager) {

        this.jwtTokenProvider = jwtTokenProvider;
        this.userRepository = userRepository;
        this.authenticationManager = authenticationManager;
    }

    @RequestMapping(value = "/{username}",method = RequestMethod.POST)
        public ResponseEntity signIn(@PathVariable String username) {
        try {
            UserModel userModel = userRepository.findByUsername(username).orElseThrow(()
                    -> new UsernameNotFoundException("Username " + username + "not found"));
            //TODO thinking about authenticationManager
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, null));
            String token = jwtTokenProvider.createToken(username, Role.TEAM.name());
            Map<Object, Object> model = new HashMap<>();
            model.put("model", userModel);
            model.put("token", token);
            return ok(model);
        } catch (AuthenticationException e) {
            throw new BadCredentialsException("Invalid username/password supplied or account locked");
        }
    }

    @RequestMapping(value = "/admin", method = RequestMethod.POST)
    public ResponseEntity signInAdmin(@RequestBody AuthForm authForm) {
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(authForm.getUsername(), authForm.getPassword()));
            String token = jwtTokenProvider.createToken(authForm.getUsername(), this.userRepository.findByUsername(authForm.getUsername()).orElseThrow(()
                    -> new UsernameNotFoundException("Username " + authForm.getUsername() + "not found")).getRole().name());

            Map<Object, Object> model = new HashMap<>();
            model.put("username", authForm.getUsername());
            model.put("token", token);
            return ok(model);
        } catch (AuthenticationException e) {
            throw new BadCredentialsException("Invalid username/password supplied or account locked");
        }
    }


}
