package com.github.reubuisnessgame.gamebank.authservice.controller;

import com.github.reubuisnessgame.gamebank.authservice.form.AuthForm;
import com.github.reubuisnessgame.gamebank.authservice.model.Role;
import com.github.reubuisnessgame.gamebank.authservice.model.UserModel;
import com.github.reubuisnessgame.gamebank.authservice.repository.UserRepository;
import com.github.reubuisnessgame.gamebank.authservice.security.jwt.JwtTokenProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

import static org.springframework.http.ResponseEntity.ok;

@RestController
@RequestMapping("/login")
public class AuthController {

    private Logger LOGGER = LoggerFactory.getLogger(AuthController.class.getSimpleName());

    private final AuthenticationManager authenticationManager;

    private final
    JwtTokenProvider jwtTokenProvider;

    private final
    UserRepository userRepository;

    private final PasswordEncoder passwordEncoder;

    @Autowired
    public AuthController(JwtTokenProvider jwtTokenProvider, UserRepository userRepository, AuthenticationManager authenticationManager, PasswordEncoder passwordEncoder) {

        this.jwtTokenProvider = jwtTokenProvider;
        this.userRepository = userRepository;
        this.authenticationManager = authenticationManager;
        this.passwordEncoder = passwordEncoder;
    }

    @RequestMapping(value = "/", method = RequestMethod.GET)
    public ResponseEntity lok(){
        return ok("OK HELLO");
    }

    @RequestMapping(value = "/{username}", method = RequestMethod.POST)
    public ResponseEntity signIn(@PathVariable(value = "username") String username ) {
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, "team"));
            String token = jwtTokenProvider.createToken(username, Role.TEAM.name());
            Map<Object, Object> model = new HashMap<>();
            model.put("username", username);
            model.put("role", "TEAM");
            model.put("token", token);
            return ok(model);
        } catch (AuthenticationException e) {
            throw new BadCredentialsException("Invalid username/password supplied or account locked");
        }
    }

    @RequestMapping(value = "/admin", method = RequestMethod.POST, produces = MediaType.APPLICATION_JSON_VALUE, consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity signInAdmin(@RequestBody AuthForm authForm) {
        try {
            UserModel userModel = userRepository.findByUsername(authForm.getUsername()).orElse(null);
            if (userModel == null) {
                LOGGER.warn("NULL USER ALERT!!!");
                return ResponseEntity.badRequest().build();
            } else {
                LOGGER.warn("Finding user " + authForm.getUsername() + " Is password ok " +
                        passwordEncoder.matches(authForm.getPassword(), userModel.getPassword()));
            }

            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(authForm.getUsername(), authForm.getPassword()));
            LOGGER.warn("Authorization OK with user " + userModel.getUsername());
            String token = jwtTokenProvider.createToken(authForm.getUsername(), this.userRepository.findByUsername(authForm.getUsername()).orElseThrow(()
                    -> new UsernameNotFoundException("Username " + authForm.getUsername() + "not found")).getRole().name());

            Map<Object, Object> model = new HashMap<>();
            model.put("username", authForm.getUsername());
            model.put("role", userModel.getRole());
            model.put("token", token);
            return ok(model);
        } catch (AuthenticationException e) {
            throw new BadCredentialsException("Invalid username/password supplied or account locked");
        }
    }


}
