package com.github.tmh0n3y;

import java.util.Base64;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

@RestController
public class AuthController {

    @GetMapping("/auth")
    public ResponseEntity<AuthResponse> validateJwt(@RequestHeader(value = "Authorization", required = false) String authHeader) { //get auth header without throwing exception if null

        // is the header format ok
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.badRequest().body(new AuthResponse(false, "Missing or invalid Authorization header format."));
        }

        // cut bearer prefix and get token and its parts
        String token = authHeader.substring(7).trim();
        String[] parts = token.split("\\."); //[0] = header [1] = payload [2] = signature

        //check if the token has 3 parts
        if (parts.length != 3) {
            return ResponseEntity.badRequest().body(new AuthResponse(false, "Invalid JWT format."));
        }

        //header contains the x5u value that we need to decode from base64 to standard json
        String x5uUrl = null;
        try {
            String headerJson = new String(Base64.getUrlDecoder().decode(parts[0])); 

            ObjectMapper mapper = new ObjectMapper();
            JsonNode headerNode = mapper.readTree(headerJson);
            if (headerNode.has("x5u")) {
                x5uUrl = headerNode.get("x5u").asText();
            }
        } catch (Exception e) {
           return ResponseEntity.badRequest().body(new AuthResponse(false, "Failed to decode or parse JWT header."));
        }

        //after all checks passed its valid!!
        return ResponseEntity.ok(new AuthResponse(true));
    }
}
