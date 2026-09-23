package com.github.tmh0n3y;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Entry point for the JWT Validator.
 */
@SpringBootApplication
public class Main {

    /**
     * Starts the Spring Boot application and embedded web server.
     *
     * @param args command-line arguments passed during startup
     */
    public static void main(String[] args) {
        SpringApplication.run(Main.class, args);
    }
}